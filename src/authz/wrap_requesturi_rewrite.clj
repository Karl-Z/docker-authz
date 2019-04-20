(ns authz.wrap-requesturi-rewrite
  (:require [authz.core :refer :all])
  (:require [clojure.string :as str])
  (:require [ring.util.response :as response])
  (:require [clojure.tools.logging :as log]))


(defn- rewrite-uri
  [uri pattern transform]
  (when (and uri pattern transform)
    (let [result (str/replace uri pattern transform)]
      (log/debugf "wrap-requesturi-rewrite: rewrite uri '%s' => '%s'" uri result)
      result)))

(defwrapper wrap-requesturi-rewrite
  :hook wrap-requesturi-rewrite-hook
  :input-path [:body "RequestUri"]
  :output-path [:body "RequestUri"]
  :args [#"/containers/([^/?]{5,})(/?[^?]*)\??(.*)$" "/containers$2?containers=$1&$3"])

;; /v1.26/containers/1938c19db6b9ef6ba35f52859748ff7c9cc86cd4231f5707ee1613dac348697a/attach?stderr=1&stdout=1&stream=1'


(add-hook wrap-requesturi-rewrite-hook rewrite-uri)


