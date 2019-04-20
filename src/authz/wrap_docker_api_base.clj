(ns authz.wrap-docker-api-base
  (:require [authz.core :refer :all])
  (:require [clojure.tools.logging :as log]))


(defn- retrieve-base
  "Find api version from the request uri"
  [reqbody]
  {:pre [(or (nil? reqbody)
             (map? reqbody))]}
  (if-let [uri (get reqbody "RequestUri")]
    (let [[_ base url]
          (re-find #"^(/[^/]+)(/.*)" uri)]
      (if base
        (assoc reqbody "RequestUri" url "RequestBase" base)
        reqbody))
    reqbody))

;; Middleware for adding peer host info
;; normally, it is the docker engine
(defwrapper wrap-docker-api-base
  :hook wrap-docker-api-base-hook
  :input-path [:body]
  :output-path [:body])

(add-hook wrap-docker-api-base-hook retrieve-base)
