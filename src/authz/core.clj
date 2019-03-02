(ns authz.core
  (:require [clojure.string :as str])
  (:require [clojure.set :refer :all])
  (:require [clojure.data.csv :as csv])
  (:require [clojure.java.io :as io])
  (:require [clojure.tools.logging :as log])
  (:require [ring.util.request :as request])
  (:require [ring.util.response :as response])
  (:require [ring.middleware.defaults :refer :all])
  (:require [ring.middleware.json :refer :all])
  (:require [compojure.core :refer :all]
            [compojure.route :as route]
            [compojure.handler :as handler]))

;; txt file driver, file type like /etc/passwd
;; args: map of driver specification:
;;      {:path "path-to-file" :column "column number to get"}

(defn passwd
  [{:keys [path column separator quote match]
    :or {column 0, separator \:, quote \"}
    :as conn}]
  (->>
   (with-open [reader (io/reader path)]
     ;; a lazy sequence of vectors of strings
     (doall (csv/read-csv reader :separator separator :quote quote)))
   (map #(nth % column))
   (#(if match (filter (partial re-matches (re-pattern match)) %) %))
   (into #{})))

;; parse file as linux group file format
;; return a map, key is gorup name
;; value is a set of users
;; eg:
;;    {"grp1" #{"usr1" "usr2"},
;;     "grp2" #{"usr3" "usr4"}}
(defn group
  [{:keys [path separator quote match]
    :or {separator \:, quote \"}
    :as conn}]
  (->>
       (with-open [reader (io/reader path)]
         (doall (csv/read-csv reader :separator separator :quote quote)))
       (reduce (fn [m [k & v]]
                 (assoc m k (set v))) {})))

;; given a name, lookup the group map,
;; return all groups which contains the name
(defn name->groups [name grps]
  (->> (keys grps)
       (filter #((get grps %) name))
       (set)))

(defn name->group [name grps]
  (->> (keys grps)
       (filter #((get grps %) name))
       (first)))

;; source definition
(defmacro defsource
  "Data source name is also a function name, which will accept one argument,
  and return true if it is known, false/nil otherwise."
  [name & {handler :type, parameters :parameters, cache :cache}]
  (let [fbody# 
        `(fn
           ([] (~handler ~parameters))
           ([arg#] (get (~name) arg#)))]
    `(def ~name
       ~(if cache (list 'memoize fbody#) fbody#))))


(defmacro defrule
  "Rule is actually a validator, its argument is the json of request"
  [name & {:keys [path validator type transform]}]
  `(def ~name
     (fn* ([request#]
           (log/debug "call rule: " (quote ~name))
           (log/debug "check request path: " ~path)
           (log/debug "request path value: " (get-in request# ~path))
           (when ~transform
             (log/debug "transformed path: " 
                        (reduce (fn [res# [pat# rep#]]
                                  (str/replace res# (re-pattern pat#) rep#))
                                (get-in request# ~path) (partition 2 ~transform))))
           (log/debug "validator: " ~validator)
           (let [pathval#
                 (get-in request# ~path)

                 tpathval#
                 (if ~transform
                   (reduce (fn [res# [pat# rep#]]
                             (str/replace res# (re-pattern pat#) rep#))
                           pathval# (partition 2 ~transform)  )
                   pathval#)
                 
                 result#
                 (if tpathval#
                   (~validator tpathval#)
                   (if (= :optional ~type) true
                       false))]
             (log/debugf "RULE '%s' result: %s" (quote ~name) result#)
             result#)))))


(defn re-subset?
  "Is set1 a subset of set2 comparing by re-matches?
  Eg: (re-subset? #{\"aa\" \"bb\"} #{#\"a.\" #\"b.\"}) => true"
  [set1 set2]
  (every? true?
          (for [s1 set1]
            (some boolean
                  (for [s2 set2]
                    (re-matches (re-pattern s2) s1))))))

;; lookup macro to define lookups
(defmacro deflookup
  "lookup something from a collection of groups, return all groups which have it"
  [name & {:keys [dominion return]}]
  `(if ~dominion
    (let [dom# (reduce into {}
                        (map #(%) ~dominion))]
       (def ~name
         (fn* ([] (~return dom#))
              ([name#]
               (~return name# dom#)))))
    (def ~name
      (fn* ([] (~return))
           ([name#]
             (~return name#)))))
  )

(defmacro add-hook
  "Add callback to wrapper"
  [hook func]
  `(reset! ~hook ~func))

; Macro for easier definition of wrapper
(defmacro defwrapper
  "Define a ring middleware for injection of lookup function"
  [name & {:keys [hook input-path output-path args]}]
  `(do
     (def ~hook (atom nil))
     (defn ~name [handler#]
       (fn [request#]
         (log/debugf "%s: request get: %s"
                     (quote ~name)
                     (if (get-in request# [:body "RequestPeerCertificates"])
                       (-> request#
                           (update-in [:body "RequestPeerCertificates"]
                                      #(identity %2) "..."))
                       request#)
                     (log/debug "request type: " (type request#)))
         (log/debug "input-path: "  ~input-path)
         (log/debug "output-path: " ~output-path)
         (log/debug "hook: " (deref ~hook))
         (when ~input-path
           (log/debug "get-in request from input-path: " (get-in request# ~input-path)))
         (if ~input-path
           (log/debug "hook result: " ((deref ~hook) (get-in request# ~input-path)))
           (log/debug "hook result without input-path: "
                    ((deref ~hook))))
         
         (if (deref ~hook)
           (let [val# (if ~input-path
                             ((deref ~hook) (get-in request# ~input-path) ~@args)
                             ((deref ~hook) ~@args))
                 req# (if val# 
                        (assoc-in request# ~output-path val#)
                        request#)]
             (log/debugf "%s: request put: %s" (quote ~name)
                         (if (get-in req# [:body "RequestPeerCertificates"])
                           (-> req#
                               (update-in [:body "RequestPeerCertificates"]
                                          #(identity %2) "..."))
                           req#))
             (handler# req#))
           (handler# request#))))))


;; policy pool is a set, key is the api version (base), value is a vector of policies
(def ^:dynamic *policy-pool* (atom {}))

;; policy definitions
(defmacro defpolicy
  "Policy is actually a function, which accept only a json as request, and go
  thru the rules, return boolean value based on the rules' return values and condition.

  Available keys:
    :base - docker api version, used as base in uri, eg: #{\"/v1.26\"}
    :uri - request uri without base part
    :rules - a group of rules applied to the request
    :condition - return true or false based on condition applied to the result of applying rules
       Values:
         :all  all rules must return true
         :some at least one rule returns true
         :one  only one rule returns true
         :none none of the rules reburns true
   
    :control - Inspired by PAM, indicates the behavior of the authorization
               should the policy fail to succeed in its authorization task
       Values:
         :required
             Failure of such a policy will ultimately lead to the autorization returning failure
             but only after the remaining stacked policies have been invoked.
    
         :requisite
             Like required, however, in the case that such a policy returns a failure, control is directly returned.
    
         :sufficient
             If such a policy succeeds and no prior required policy has failed,
             control returns success without calling any further policies in the stack.
             A failure of a sufficient policy is ignored and processing of other policies in the stack continues unaffected.
    
         :optional
             the success or failure of this policy is only important if it is the only policy in the stack."
  [name & {:keys [base uri rules condition control] :or {condition :all control :required}}]
  (let [fsym# (if (= '_ name) (gensym "anonymous-policy-") name)] ;; fsym#: function name
    `(do
       (def ~fsym#
         (fn* ([request#]
               (log/debugf "'%s' policy checking" (quote ~fsym#))
               (log/debug "RequestUri: " (get-in request# [:body "RequestUri"]))
               (log/debug "uri pattern: " ~uri)
               (log/debug "rules to apply: " ~rules)
               (log/debug "result condition: " ~condition)
               #_(let [r# (map #(% request#) ~rules)]
                 (log/debug "applied result number of elements: " (count r#))
                 (log/debug "applied result: " (map boolean r#)))
               (let [result#
                     (condp = ~condition
                       :all
                       (every? boolean 
                               (map #(% request#) ~rules))
                       :some
                       (some boolean 
                             (map #(% request#) ~rules))
                       :one
                       (= 1 (count (filter boolean
                                           (map #(% request#) ~rules))))
                       :none
                       (every? (comp not boolean)
                               (map #(% request#) ~rules))
                       )]
                 (log/debugf "POLICY '%s' result: %s" (quote ~fsym#) result#)
                 result#))))
       
       ;; update policy-pool, append policy
       (let [pol# [(re-pattern ~uri) ~fsym# ~control]]
         (doseq [bs# ~base]
           (swap! *policy-pool*
                  update-in [bs#]
                  #(if %1 (conj %1 %2) [%2])
                  pol#)))

       ;; return the function as policy
       ~fsym#)))

 ;; if-let multiple bindings version
(defmacro if-let*
  ([bindings then]
   `(if-let* ~bindings ~then nil))
  ([bindings then else]
   (if (seq bindings)
     `(if-let [~(first bindings) ~(second bindings)]
        (if-let* ~(drop 2 bindings) ~then ~else)
        ~else)
     then)))

;; when-let multiple bindings version
(defmacro when-let*
  ([bindings & body]
   (if (seq bindings)
     `(when-let [~(first bindings) ~(second bindings)]
        (when-let* ~(drop 2 bindings) ~@body))
     `(do ~@body))))

(defn eval-policies
  "Evaluate all policies applicable and return a vector indicating the result based on the policy control.

  See `defpolicy' for values of control.

  @return: [boolean string]"
  [request-uri request]
  (let [[_ base uri] (re-find #"^(/v1\.\d\d)(/.*)" request-uri)]
    (if-let [policies-under-base
             (get @*policy-pool* base)]
      (if-let [policies-to-apply
               (map next
                    (filter #(re-matches (first %) uri)
                            policies-under-base))]
        (do
          (log/debugf "base: %s uri: %s" base uri)
          (doseq [p policies-to-apply]
            (log/debug "policy-to-apply: " p))
          (if-let
              [return-value
               (loop [ps policies-to-apply
                      final nil]

                 (if ps
                   (let [;; policy and its control
                         [pol ctr] (first ps)
                         ;; pol name as message
                         msg (str pol)
                         ;; policy appied result
                         pres (pol request)
                         ret [pres msg]]
                     (log/debugf "policy-apply-result: %s => %s" pol pres)
                     (condp = ctr
                       :required
                       (recur (next ps) [pres msg])

                       :requisite
                       (if pres
                         (recur (next ps) (when (nil? final) ret))
                         ret)

                       :sufficient
                       (if (and pres
                                (or (nil? final) (first final)))
                         ret
                         (recur (next ps) final))

                       :optional
                       (if (next ps)
                         (recur (next ps) final)
                         (if (nil? final) ret final))
                       ;; else
                       (throw (IllegalArgumentException. (str "Wrong control type: " ctr)))))
                   final))]
            return-value
            [false "All sufficient policies are failed"]))
        [true "Default permission is granted"])
      [false (str "No such version: " (subs base 1))])))

;;-----------------------------------------------------------

(defn authz-response
  "Generate a response to AUTHZREQ or AUTHZRES"
  ([allow]
   (authz-response allow (if allow "Permission granted" "Permission denied")))
  ([allow msg]
   (authz-response allow msg ""))
  ([allow msg err]
   (assert (boolean? allow))
   (assert (string? msg))
   (assert (string? err))
   (response/response
    {"Allow" allow,
     "Msg" msg,
     "Err" err})))

(defn authzreq
  [{{:strs [User UserAuthNMethod Requestmethod RequestUri
            RequestBody RequestHeader]} :body :as req}]
  (authz-response true "Permitted"))



(defn authzres
  [{{:strs [User UserAuthNMethod Requestmethod RequestUri
            RequestBody ResponseBody ResponseHeader
            ResponseStatusCode]} :body :as req}]
  (authz-response true "Permitted")
  )


;;-----------------------------------------------------------

(defroutes authz-routes
  (GET "/" [] "Docker Authz Plugin")
  (GET "/_ping" [] (authz-response true))
  (POST "/Plugin.Activate" [] (response/response {:Implements ["authz"]}))
  (POST "/AuthZPlugin.AuthZReq" req
        (if-let [request-uri (get-in req [:body "RequestUri"])]
          (condp re-matches request-uri
            #"/v1\.\d\d/.*"
            (apply authz-response
                   (eval-policies request-uri req))
            #_(let [[_ base uri] (re-find #"^(/v1\.\d\d)(/.*)" request-uri)
                  all-keys-in-policy-pool (keys (get @*policy-pool* base))
                  applied-uri-patterns (filter #(re-matches (re-pattern %) uri)
                                               (keys (get @*policy-pool* base)))
                  policies-to-apply (map #(get-in @*policy-pool* [base %]) applied-uri-patterns)
                  unique-policies-to-apply (reduce into #{} policies-to-apply)
                  policies-apply-result (doall (map #(vector % (% req)) unique-policies-to-apply))]
              (log/debugf "base: %s uri: %s" base uri)
              (log/debug "policy-pool: " @*policy-pool*)
              (log/debug "all-keys-in-policy-pool: " all-keys-in-policy-pool)
              (log/debug "applied-uri-patterns: " applied-uri-patterns)
              (log/debug "applied-policies: " policies-to-apply)
              (log/debug "unique-policies: " unique-policies-to-apply)
              (doseq [rr policies-apply-result]
                (log/debug "policy-applied-result: " rr))

              (if all-keys-in-policy-pool 
                ;; find applicable uris and collect all rules
                (if (->>
                     (filter #(re-matches (re-pattern %) uri)
                             (keys (get @*policy-pool* base)))
                     (map #(get-in @*policy-pool* [base %]))
                     (reduce into #{})
                     (map #(% req))
                     (every? boolean))
                  (authz-response true)
                  (authz-response false))
                (authz-response false (str "No such version: " base))))
            
            
            #"/_ping" (authz-response true)

            #"/version" (authz-response true)

            #".*" (authz-response false)
            )
          (authz-response false)))
  (POST "/AuthZPlugin.AuthZRes" req
        (authz-response true)))

