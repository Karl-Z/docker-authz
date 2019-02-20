(ns authz.core
  (:require [clojure.string :as str])
  (:require [clojure.set :refer :all])
  (:require [clojure.data.csv :as csv])
  (:require [clojure.java.io :as io])
  (:require [clojure.tools.logging :as log])
  (:require [clj-dns.core :as dns])
  (:require [ring.util.request :as request])
  (:require [ring.util.response :as response])
  (:require [ring.middleware.defaults :refer :all])
  (:require [ring.middleware.json :refer :all])
  (:require [compojure.core :refer :all]
            [compojure.route :as route]
            [compojure.handler :as handler])
  )

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
   (#(if match (filter (partial re-matches (re-pattern ~match)) %) %))
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
           (log/debug "path: " (get-in request# ~path))
           (when ~transform
             (log/debug "transformed path: " 
                        (reduce (fn [res# [pat# rep#]]
                                  (str/replace res# (re-pattern pat#) rep#))
                                (get-in request# ~path) (partition 2 ~transform))))
           (log/debug "validator: " ~validator)
           (let [pathval# (get-in request# ~path)
                 tpathval# (if ~transform
                             (reduce (fn [res# [pat# rep#]]
                                       (str/replace res# (re-pattern pat#) rep#))
                                     pathval# (partition 2 ~transform)  )
                             pathval#)]
             (if tpathval#
               (~validator tpathval#)
               (if (= :optional ~type) true
                   false)))))))


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
                     (-> request#
                         (update-in [:json-params "RequestPeerCertificates"]
                                    #(identity %2) "...")
                         (update-in [:params "RequestPeerCertificates"]
                                    #(identity %2) "..."))
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
           (let [req# 
                 (assoc-in request# ~output-path
                           (if ~input-path
                             ((deref ~hook) (get-in request# ~input-path))
                             ((deref ~hook))))
                        ]
             (log/debugf "%s: request put: %s" (quote ~name)
                         (-> req#
                         (update-in [:json-params "RequestPeerCertificates"]
                                    #(identity %2) "...")
                         (update-in [:params "RequestPeerCertificates"]
                                    #(identity %2) "...")))
             (handler# req#))
           (handler# request#))))))

;; Reverse lookup ip-addr, if found, return DNS name
;; otherwise, return IP
(defn find-hostname
  "Find localhost's canonial name"
  [ipaddr]
  (try
    (str/trim (dns/reverse-dns-lookup ipaddr))
    (catch java.net.UnknownHostException e
      ipaddr)))

;; lookup for host
(deflookup host-lookup
  :return find-hostname)


;; Middleware for adding peer host info
;; normally, it is the docker engine
(defwrapper wrap-host-param
  :hook wrap-host-param-hook
  :input-path [:remote-addr]
  :output-path [:params "Host"])

;; Middleware for adding host group info
(defwrapper wrap-hostgroups-param
  :hook wrap-hostgroups-param-hook
  :input-path [:params "Host"]
  :output-path [:params "HostGroup"])

;; Middleware for adding user group info
(defwrapper wrap-usergroups-param
  :hook wrap-usergroups-param-hook
  :input-path [:params "User"]
  :output-path [:params "UserGroup"])

;; Middleware for adding deployment environment
(defwrapper wrap-deploymentenvironments-param
  :hook wrap-deploymentenvironments-param-hook
  :input-path [:params "HostGroup"]
  :output-path [:params "DeploymentEnvironment"])

;; Add some hooks
(add-hook wrap-host-param-hook host-lookup)


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
;;            :one only one rule returns true
;;            :none none of the rules reburns true

(defmacro defpolicy
  "policy is actually a function, which accept only a json as request, and go thru the rules, return true only if all rules return true."
  [name & {:keys [base uri rules condition] :or {condition :all}}]
  (let [fsym# (if (= '_ name) (gensym "anonymous-policy-") name)] ;; fsym#: function name
    `(do
       (def ~fsym#
         (fn* ([request#]
               (log/debugf "'%s' policy request: %s" (quote ~fsym#) request#)
               (log/debug "rules: " ~rules)
               (log/debug "RequestURI: " (get-in request# [:params "RequestURI"]))
               (log/debug "uri pattern: " ~uri)
               (let [r# (map #(% request#) ~rules)]
                 (log/debug "applied result number of elements: " (count r#))
                 (log/debug "applied result: " (map boolean r#))
                 (log/debug "applied condition: " ~condition))
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
                 ))))
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
  [{{:strs [User UserAuthNMethod Requestmethod RequestURI
            RequestBody RequestHeader]} :params :as req}]
  (authz-response true "Permitted"))



(defn authzres
  [{{:strs [User UserAuthNMethod Requestmethod RequestURI
            RequestBody ResponseBody ResponseHeader
            ResponseStatusCode]} :params :as req}]
  (authz-response true "Permitted")
  )


(defroutes authz-routes
  (GET "/" [] "Docker Authz Plugin")
  (GET "/_ping" [] (authz-response true))
  (POST "/Plugin.Activate" [] (response/response {:Implements ["authz"]}))
  (POST "/AuthZPlugin.AuthZReq" req
        (if-let [request-uri (get-in req [:params "RequestUri"])]
          (condp re-matches request-uri
            #"/v1\.\d\d/.*"
            (let [[_ base uri] (re-find #"^(/v1\.\d\d)(/.*)" request-uri)
                  all-keys-in-policy-pool (keys (get @*policy-pool* base))
                  applied-uri-patterns (filter #(re-matches (re-pattern %) uri)
                                               (keys (get @*policy-pool* base)))
                  applied-rules (map #(get-in @*policy-pool* [base %]) applied-uri-patterns)
                  reduced-rules (reduce into #{} applied-rules)
                  rule-apply-result (doall (map #(% req) reduced-rules))]
              (log/debugf "base: %s uri: %s" base uri)
              (log/debug "policy-pool: " @*policy-pool*)
              (log/debug "all-keys-in-policy-pool: " all-keys-in-policy-pool)
              (log/debug "applied-uri-patterns: " applied-uri-patterns)
              (log/debug "applied-rules: " applied-rules)
              (log/debug "reduced-rules: " reduced-rules)
              (log/debug "rule-apply-result: " rule-apply-result)

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

