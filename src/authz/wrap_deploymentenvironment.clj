(ns authz.wrap-deploymentenvironment
  (:require [authz.core :refer :all])
  (:require [clojure.string :as str])
  (:require [ring.util.response :as response])
  (:require [clojure.tools.logging :as log]))

;; Middleware for adding deployment environment
(defwrapper wrap-deploymentenvironment
  :hook wrap-deploymentenvironment-hook
  :input-path [:body "HostGroup"]
  :output-path [:body "DeploymentEnvironment"])
