(ns authz.core
  (:require [clojure.string :as str])
  (:require [clojure.pprint :refer [pprint]])
  (:require [clojure.set :refer :all])
  (:require [clojure.data.csv :as csv])
  (:require [clojure.java.io :as io])
  (:require [clojure.tools.logging :as log])
  (:require [authz.utils :refer :all])
  (:require [ring.util.request :as request])
  (:require [ring.util.response :as response])
  (:require [compojure.core :refer [defroutes GET POST PUT DELETE]])
  (:import java.util.UUID))


;; *policy-pool* is a set, key is the api version (base), value is a vector of policies
(def ^:dynamic *policy-pool* (atom {}))

;; *docker-api-versions* is the policy applied docker request version
(def ^:dynamic *docker-api-versions* (atom #{}))

;; *default-add-policy-control* is the policy default control value
(def ^:dynamic *default-add-policy-control* (atom :required))

;; *default-add-policy-context* is the default context, which is set to always true
(def ^:dynamic *default-add-policy-context* (atom (constantly true)))

;; *default-permission* is the boolean value to response if the request does not match any
(def ^:dynamic *default-permission* (atom false))

;; config file directory
(def ^:dynamic *config-directory* (atom false))

(defn- abspath [path]
  (if (str/starts-with? path "/")
    path
    (str @*config-directory* "/" path)))

;; txt file driver, file type like /etc/passwd
;; args: map of driver specification:
;;      {:path "path-to-file" :column "column number to get"}
(defn passwd
  "Linux passwd file like format with user name at first column.
  Returns a set contains user names."
  [{:keys [path column separator quote match]
    :or {column 0, separator \:, quote \"}
    :as conn}]
  (log/debug "open file as passwd: " path)
  (->>
   (with-open [reader (io/reader (abspath path))]
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
  "Linux group file like format with group name at first column.
  Returns a hash map, key is group name, value is a set of group members.

  Example return value:
     {\"grp1\" #{\"usr1\" \"usr2\"},
      \"grp2\" #{\"usr3\" \"usr4\"}}"
  [{:keys [path separator quote match]
    :or {separator \:, quote \"}
    :as conn}]
  (->>
   (with-open [reader (io/reader (abspath path))]
     (doall (csv/read-csv reader :separator separator :quote quote)))
   (reduce (fn [m [k & v]]
             (assoc m k (set v))) {})))

;; given a name, lookup the group map,
;; return all groups which contains the name
(defn name->groups [name groups]
  "Returns group names by looking up the name from the groups"
  (->> (keys groups)
       (filter #((get groups %) name))
       (set)))

(defn name->group [name groups]
  "Returns the first group found in the grps which contains the name."
  (->> (keys groups)
       (filter #((get groups %) name))
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


(defrecord Rule [path validator transform]
  clojure.lang.IFn
  (invoke [this request]
    (let [pathval
          (get-in request path)

          tpathval
          (if transform
            (reduce (fn [res [pat rep]]
                      (str/replace res (re-pattern pat) rep))
                    pathval (partition 2 transform)  )
            pathval)
                
          result
          (validator tpathval)]
      (log/debugf "rule apply result: %s => %s" [path validator transform] result)
      result))
  (invoke [this] (.hashCode this))
  (applyTo [this arglist]
    (eval (cons (identity this) arglist))))

(defmacro defrule
  "Returns a named function as a rule.
  
  Parameters:
    path        - a path info in request to get the value to feed the validator
    validator   - a function requires the same arguments as paths indicated
    transform   - a array of regexp pattern and replacement to manipulate path value"
  [name & {:keys [path validator transform]}]
  `(def ~name
     (->Rule ~path ~validator ~transform)))

(defn rule [path validator & [transform]]
  (->Rule path validator transform))

;; lookup macro to define lookups
(defmacro deflookup
  "Lookups something from a collection of groups, returns all groups which have it."
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
             (~return name#))))))

(defmacro add-hook
  "Adds a callback to a wrapper."
  [hook func]
  `(reset! ~hook ~func))

;; Macro for easier definition of wrapper
(defmacro defwrapper
  "Creates a ring middleware for injection of lookup function."
  [name & {:keys [hook input-path output-path args]}]
  `(do
     (def ~hook (atom nil))
     (defn ~name [handler#]
       (fn [request#]
         (log/debugf "%s: request get:\n%s"
                     (quote ~name)
                     (with-out-str (pprint
                                    (if (get-in request# [:body "RequestPeerCertificates"])
                                      (-> request#
                                          (update-in [:body "RequestPeerCertificates"]
                                                     #(identity %2) "..."))
                                      request#)))
                     (log/debug "request type: " (type request#)))
         (log/debug "input-path: "  ~input-path)
         (log/debug "output-path: " ~output-path)
         (log/debug "hook: " (deref ~hook))
         
         (if (deref ~hook)
           (let [val# (if ~input-path
                             ((deref ~hook) (get-in request# ~input-path) ~@args)
                             ((deref ~hook) ~@args))
                 req# (if val# 
                        (assoc-in request# ~output-path val#)
                        request#)]
             (log/debugf "%s: request put:\n%s" (quote ~name)
                         (with-out-str (pprint
                                        (if (get-in req# [:body "RequestPeerCertificates"])
                                          (update-in req# [:body "RequestPeerCertificates"]
                                                     #(identity %2) "...")
                                          req#))))
             (handler# req#))
           (do1 (handler# request#)
                (log/debugf "%s is done" ~name)))))))

(defrecord Policy [condition rules]
  clojure.lang.IFn
  (invoke [this] (.hashCode this))
  (invoke [this request]
    (log/debug "policy checking: " (.hashCode this))
    (log/debug "RequestUri: " (get-in request [:body "RequestUri"]))
    (log/debug "RequestMethod: " (get-in request [:body "RequestMethod"]))
    (log/debug "rules to apply: " rules)
    (condp = condition
      :all
      (every? boolean 
              (map #(% request) rules))
      :some
      (some boolean 
            (map #(% request) rules))
      :one
      (= 1 (count (filter boolean
                          (map #(% request) rules))))
      :none
      (every? (comp not boolean)
              (map #(% request) rules))

      (throw (IllegalArgumentException. (str "Unknow condition: " condition)))))
  (applyTo [this arglist]
    (eval (cons (identity this) arglist))))


(defmacro defpolicy
    "Policy is actually a function, which accepts a map as request, and goes
  thru the rules, returns a boolean value based on the rules' return values and condition.

  Available keys:
    :rules      - Rules to apply be validated
    :policies   - Policies to be grouped into one big policy
    :condition  - Return true or false based on condition applied to the result of rules
                  possible values:
                  :all   - all rules must return true
                  :some  - at least one rule returns true
                  :one   - only one rule returns true
                  :none  - none of the rules reburns true"

  [name & {:keys [condition rules policies]
           :or {condition :all}}]
  `(def ~name
     (->Policy ~condition [~@rules ~@policies])))

(defn policy
  [condition & rules]
  (->Policy condition rules))

(defmacro defcontext
  "Creates a context predictor. (alias to defpolicy)"
  [& args]
  `(defpolicy ~@args))

(defn add-policy
  "Adds a policy to the policy execution pool, and returns a uuid number as token for reference.

  Possible parameters:
      :versions    - policy only apply to the specific api versions(a set), default is *docker-api-versions*
      :context    - Validate the policies only when the context matches, otherwise, skipped policy checking.
      :control    - Inspired by PAM, indicates the behavior of the authorization
                    should the policy fail to succeed in its authorization task.
                    Possible values:
                    :required    - Failure of such a policy will ultimately lead to the autorization returning failure, but only after the remaining stacked policies have been invoked.
                    :requisite   - Like required, however, in the case that such a policy returns a failure, control is directly returned.
                    :sufficient  - If such a policy succeeds and no prior required policy has failed,
                                   Control returns success without calling any further policies in the stack.
                                   A failure of a sufficient policy is ignored and processing of other policies in the stack continues unaffected.
                    :optional   - The success or failure of this policy is only important if it is the only policy in the stack."
  [description policy & {:keys [versions control context]
             :or {versions @*docker-api-versions*
                  control @*default-add-policy-control*
                  context @*default-add-policy-context*}}]
  (let [token (UUID/randomUUID)
        pol [token description context policy control]]
    (doseq [ver versions]
      (swap! *policy-pool*
             update-in [ver]
             #(if %1 (conj %1 %2) [%2])
             pol))
    (log/debugf "add-policy (queued id: %s) => %s " token (policy))
    token))

(defn eval-policies
  "Evaluates all applicable policies and returns a vector as result based on the policy control.

  See `add-policy' for the values of control.

  @return: [boolean string]"
  [request]
  (let [uri (get-in request [:body "RequestUri"])
        ver (subs (get-in request [:body "RequestBase"]) 2)]
    (log/debug "eval-policies for version: " ver)
    (if-let [policies-under-version (get @*policy-pool* ver)]
      (do (log/debugf "eval-policies: found policies under version: %s" ver)
          (if-let [policies-to-apply
                   (filter (fn [[id desc ctx plc ctr]] (ctx request)) ; filter only relative policies
                           policies-under-version)]
            (let [return-value
                 (loop [ps policies-to-apply
                        final nil]
                   (if ps
                     (let [;; policy and its control
                           [id desc ctx plc ctr] (first ps)
                           ;; policy appied result
                           pres (plc request)
                           ;; pol name as message
                           msg (str "policy("id") verification " (if pres "succceed: " "failed: ")
                                    desc " ("(name ctr)")")
                           ret [pres msg]]
                       (log/debugf "policy apply result: %s => %s (%s)" plc pres ctr)
                       (condp = ctr
                         :required
                         (if pres
                           (recur (next ps) (if (nil? final) ret final))
                           (recur (next ps) ret))

                         :requisite
                         (if pres
                           (recur (next ps) (if (nil? final) ret final))
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
              (if (nil? return-value) [false "Policy verification failed"]
                  return-value))
            [@*default-permission* "Default permission applied"]))
      [false (do (log/debugf "eval-policies: failed with version")
                 (str "No such version: " ver))])))

;;-----------------------------------------------------------

(defn authz-response
  "Generate a response to a AUTHZREQ or AUTHZRES request."
  ([allow]
   (authz-response allow (if allow "Permission granted" "Permission denied")))
  ([allow msg]
   (authz-response allow msg ""))
  ([allow msg err]
   (response/response
    {"Allow" (boolean allow),
     "Msg" (str msg),
     "Err" (str err)})))

(defn- replace-RequestPeerCertificates
  ([req]
   (replace-RequestPeerCertificates req "..."))
  ([req repl]
   (assoc-in req [:body "RequestPeerCertificates"] repl)))

;;-----------------------------------------------------------

(defroutes authz-routes
  (GET "/" [] "Docker Authz Plugin")
  (GET "/_ping" [] (authz-response true))
  (POST "/Plugin.Activate" [] (response/response {:Implements ["authz"]}))
  (POST "/AuthZPlugin.AuthZReq" req
        (apply authz-response
               (when-let [request-uri (get-in req [:body "RequestUri"])]
                 (condp re-matches request-uri
                   #"/_ping" [true]
                   #"/version" [true]
                   (eval-policies req)))))
  (POST "/AuthZPlugin.AuthZRes" res (authz-response true)
        #_(apply authz-response
               (eval-policies res))))

