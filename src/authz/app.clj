(ns authz.app
  (:require [authz.core :refer :all])
  (:require [ring.middleware.defaults :refer :all])
  (:require [ring.middleware.json :refer :all])
  (:require [authz.contenttype :refer :all])
  (:require [ring.middleware.logger :refer :all])
)

;; Load config file
(load "config")

(def app
  (-> authz-routes
      (wrap-usergroups)
      (wrap-deploymentenvironments)
      (wrap-hostgroups)
      (wrap-host)
      (wrap-body-requesturi)
      (wrap-responsebody-decode)
      (wrap-requestbody-decode)
      (wrap-json-body)
      (wrap-json-response)
      (wrap-content-type :request "application/json")
      (wrap-defaults api-defaults)
      (wrap-with-logger)))

