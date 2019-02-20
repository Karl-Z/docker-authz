(ns authz.app
  (:require [authz.core :refer :all])
  (:require [ring.middleware.defaults :refer :all])
  (:require [ring.middleware.json :refer :all])
  (:require [authz.contenttype :refer :all])
  #_(:require [ring.middleware.logger :refer :all])
)

;; Load config file
(load "config")

(def app
  (-> authz-routes
      (wrap-usergroups-param)
      (wrap-deploymentenvironments-param)
      (wrap-hostgroups-param)
      (wrap-host-param)
      (wrap-json-body)
      (wrap-json-params)
      (wrap-json-response)
      (wrap-content-type :request "application/json")
      (wrap-defaults api-defaults)
      #_(wrap-with-logger)))

