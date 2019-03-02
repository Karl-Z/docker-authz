(ns authz.wrap-requestbody-decode
  (:require [authz.core :refer :all])
  (:require [clojure.string :as str])
  (:require [ring.util.response :as response])
  (:require [clojure.tools.logging :as log])
  (:require [cheshire.core :as json])
  (:require [ring.util.codec :as codec]))

;; Handle ResponseBody in request's [:body "ResponseBody"] key
(defwrapper wrap-requestbody-decode
  :hook wrap-requestbody-decode-hook
  :input-path [:body "RequestBody"]
  :output-path [:body "RequestBody"])

;; Decode ResponseBody
(add-hook wrap-requestbody-decode-hook
          #(when % (json/parse-string (slurp (codec/base64-decode %)))))

