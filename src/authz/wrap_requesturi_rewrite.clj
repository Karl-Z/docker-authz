(ns authz.wrap-requesturi-rewrite
  (:require [authz.core :refer :all])
  (:require [clojure.string :as str])
  (:require [ring.util.response :as response])
  (:require [clojure.tools.logging :as log]))


(defn- rewrite-uri
  [uri rule result]
  (log/debugf "rewrite uri '%s' from '%s' to '%s': " uri rule result)
  (when (and uri rule result)
    (str/replace uri rule result)))

(defwrapper wrap-requesturi-rewrite
  :hook wrap-requesturi-rewrite-hook
  :input-path [:body "RequestUri"]
  :output-path [:body "RequestUri"]
  :args [#"/containers/([^/?]{5,})(/?[^?]*)$" "/containers$2?containers=$1"])

(add-hook wrap-requesturi-rewrite-hook rewrite-uri)


