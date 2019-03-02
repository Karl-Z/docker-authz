(ns authz.wrap-hostgroup
  (:require [authz.core :refer :all])
  (:require [clojure.string :as str])
  (:require [ring.util.response :as response])
  (:require [clojure.tools.logging :as log]))

;; Middleware for adding host group info
(defwrapper wrap-hostgroup
  :hook wrap-hostgroup-hook
  :input-path [:body "Host"]
  :output-path [:body "HostGroup"])

