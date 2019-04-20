(ns authz.wrap-usergroup
  (:require [authz.core :refer :all])
  (:require [clojure.tools.logging :as log]))

;; Middleware for adding host group info
(defwrapper wrap-usergroup
  :hook wrap-usergroup-hook
  :input-path [:body "User"]
  :output-path [:body "UserGroup"])

