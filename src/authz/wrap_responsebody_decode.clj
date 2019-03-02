(ns authz.wrap-responsebody-decode
  (:require [authz.core :refer :all])
  (:require [clojure.string :as str])
  (:require [ring.util.response :as response])
  (:require [clojure.tools.logging :as log])
  (:require [cheshire.core :as json])
  (:require [ring.util.codec :as codec]))

(defwrapper wrap-responsebody-decode
  :hook wrap-responsebody-decode-hook
  :input-path [:body "ResponseBody"]
  :output-path [:body "ResponseBody"])

(add-hook wrap-responsebody-decode-hook
          #(when % (json/parse-string (slurp (codec/base64-decode %)))))

