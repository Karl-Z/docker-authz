(ns authz.wrap-requesturi-parse
  (:require [authz.core :refer :all])
  (:require [clojure.string :as str])
  (:require [ring.util.response :as response])
  (:require [clojure.tools.logging :as log])
  (:require [ring.util.codec :as codec])
)

;; Decode RequestUri parameters, add them in body's params
(defwrapper wrap-requesturi-parse
  :hook wrap-requesturi-parse-hook
  :input-path [:body "RequestUri"]
  :output-path [:body :params])

;; Function to parse uri and return hash of parameters in uri
(defn parse-uri
  [uri]
  (when (some #(= % \?) uri)
    (-> uri
        (str/replace #"^.*\?" "")
        (codec/form-decode))))

;; Add some hooks
(add-hook wrap-requesturi-parse-hook parse-uri)

