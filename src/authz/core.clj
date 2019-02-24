(ns authz.core
  (:require [clojure.string :as str])
  (:require [clojure.set :refer :all])
  (:require [clojure.data.csv :as csv])
  (:require [clojure.java.io :as io])
  (:require [clojure.tools.logging :as log])
  (:require [clj-dns.core :as dns])
  (:require [ring.util.request :as request])
  (:require [ring.util.response :as response])
  (:require [ring.util.codec :as codec])
  (:require [ring.middleware.defaults :refer :all])
  (:require [ring.middleware.json :refer :all])
  (:require [compojure.core :refer :all]
            [compojure.route :as route]
            [compojure.handler :as handler])
  (:require [cheshire.core :as json])
  (:require [clojure.walk :as walk]))

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
  `(swap! ~hook #(identity %2) ~func))

; Macro for easier definition of wrapper
(defmacro defwrapper
  "Define a ring middleware for injection of lookup function"
  [name & {:keys [hook input-path output-path]}]
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
                             ((deref ~hook) (get-in request# ~input-path))
                             ((deref ~hook)))
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

;; Reverse lookup ip-addr, if found, return DNS name
;; otherwise, return IP
(defn find-hostname
  "Find localhost's canonial name"
  [ipaddr]
  (let [hn
        (try
          (str/trim (dns/reverse-dns-lookup ipaddr))
          (catch java.net.UnknownHostException e
            ipaddr))]
    ;; remove ending dot
    (subs hn 0 (dec (count hn)))))

;; lookup for host
(deflookup host-lookup
  :return find-hostname)


;; Middleware for adding peer host info
;; normally, it is the docker engine
(defwrapper wrap-host
  :hook wrap-host-hook
  :input-path [:remote-addr]
  :output-path [:body "Host"])

;; Middleware for adding host group info
(defwrapper wrap-hostgroups
  :hook wrap-hostgroups-hook
  :input-path [:body "Host"]
  :output-path [:body "HostGroup"])

;; Middleware for adding user group info
(defwrapper wrap-usergroups
  :hook wrap-usergroups-hook
  :input-path [:body "User"]
  :output-path [:body "UserGroup"])

;; Middleware for adding deployment environment
(defwrapper wrap-deploymentenvironments
  :hook wrap-deploymentenvironments-hook
  :input-path [:body "HostGroup"]
  :output-path [:body "DeploymentEnvironment"])

;; Handle ResponseBody in request's [:body "ResponseBody"] key
(defwrapper wrap-requestbody-decode
  :hook wrap-requestbody-decode-hook
  :input-path [:body "RequestBody"]
  :output-path [:body "RequestBody"])

(defwrapper wrap-responsebody-decode
  :hook wrap-responsebody-decode-hook
  :input-path [:body "ResponseBody"]
  :output-path [:body "ResponseBody"])

;; Decode ResponseBody
(add-hook wrap-requestbody-decode-hook
          #(when % (json/parse-string (slurp (codec/base64-decode %)))))

(add-hook wrap-responsebody-decode-hook
          #(when % (json/parse-string (slurp (codec/base64-decode %)))))

;; Decode RequestUri parameters, add them in body
(defwrapper wrap-body-requesturi
  :hook wrap-body-requesturi-hook
  :input-path [:body "RequestUri"]
  :output-path [:body :params])

;; Function to parse uri and return hash of parameters in uri
(defn parse-uri
  [uri]
  (when (some #(= % \?) uri)
    (-> uri
        (str/replace #"^.*\?" "")
        (codec/form-decode)
        (walk/keywordize-keys))))

;; Add some hooks
(add-hook wrap-host-hook host-lookup)
(add-hook wrap-body-requesturi-hook parse-uri)

;; policy pool is a map, key is the api version, value is a vector of policies
(def ^:dynamic *policy-pool* (atom {}))

;; policy definitions
;; available keys:
;; :base - docker api version, used as base in uri
;; :uri - request uri without base part
;; :rules - a group of rules applied to the request
;; :condition - return true or false based on condition applied to the result of applying rules
;;    values: :all  all rules must return true
;;            :some at least one rule returns true
;;            :any only one rule returns true
;;            :none none of the rules reburns true

(defmacro defpolicy
  "policy is actually a function, which accept only a json as request, and go thru the rules, return true only if all rules return true."
  [name & {:keys [base uri rules condition] :or {condition :all}}]
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
                       :any
                       (= 1 (count (filter boolean
                                           (map #(% request#) ~rules))))
                       :none
                       (every? (comp not boolean)
                               (map #(% request#) ~rules))
                       )]
                 (log/debugf "POLICY '%s' result: %s" (quote ~fsym#) result#)
                 result#))))
       (doseq [bs# ~base] ; update policy-pool, append policy based on the base and uri
         (swap! *policy-pool*
                update-in [bs# ~uri]
                #(if %1 (conj %1 %2) #{%2})
                ~fsym#))
       ~fsym#)))



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


(defroutes authz-routes
  (GET "/" [] "Docker Authz Plugin")
  (GET "/_ping" [] (authz-response true))
  (POST "/Plugin.Activate" [] (response/response {:Implements ["authz"]}))
  (POST "/AuthZPlugin.AuthZReq" req
        (if-let [request-uri (get-in req [:body "RequestUri"])]
          (condp re-matches request-uri
            #"/v1\.\d\d/.*"
            (let [[_ base uri] (re-find #"^(/v1\.\d\d)(/.*)" request-uri)
                  all-keys-in-policy-pool (keys (get @*policy-pool* base))
                  applied-uri-patterns (filter #(re-matches (re-pattern %) uri)
                                               (keys (get @*policy-pool* base)))
                  rules-to-apply (map #(get-in @*policy-pool* [base %]) applied-uri-patterns)
                  unique-rules-to-apply (reduce into #{} rules-to-apply)
                  rules-apply-result (doall (map #(vector % (% req)) unique-rules-to-apply))]
              (log/debugf "base: %s uri: %s" base uri)
              (log/debug "policy-pool: " @*policy-pool*)
              (log/debug "all-keys-in-policy-pool: " all-keys-in-policy-pool)
              (log/debug "applied-uri-patterns: " applied-uri-patterns)
              (log/debug "applied-rules: " rules-to-apply)
              (log/debug "unique-rules: " unique-rules-to-apply)
              (doseq [rr rules-apply-result]
                (log/debug "rules-apply-result: " rr))

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
                (authz-response false (str "No such version: " base)))
              )
            
            #"/_ping" (authz-response true)

            #"/version" (authz-response true)

            #".*" (authz-response false)
            )
          (authz-response false)))
  (POST "/AuthZPlugin.AuthZRes" req
        (authz-response true)))

