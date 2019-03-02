(ns authz.app
  (:require [authz.core :refer :all])
  (:require [clojure.set :refer :all])
  (:require [authz.wrap-contenttype :refer :all])
  (:require [authz.wrap-host :refer :all])
  (:require [authz.wrap-hostgroup :refer :all])
  (:require [authz.wrap-usergroup :refer :all])
  (:require [authz.wrap-deploymentenvironment :refer :all])
  (:require [authz.wrap-requesturi-parse :refer :all])
  (:require [authz.wrap-requesturi-rewrite :refer :all])
  (:require [authz.wrap-requesturi-parse :refer :all])
  (:require [authz.wrap-requestbody-decode :refer :all])
  (:require [authz.wrap-responsebody-decode :refer :all])
  (:require [ring.middleware.defaults :refer :all])
  (:require [ring.middleware.json :refer :all])
  (:require [ring.middleware.logger :refer :all]))

;; Load config file
(load "config")

(def app
  (-> authz-routes
      (wrap-usergroup)
      (wrap-deploymentenvironment)
      (wrap-hostgroup)
      (wrap-host)
      (wrap-requesturi-parse)
      (wrap-requesturi-rewrite)
      (wrap-responsebody-decode)
      (wrap-requestbody-decode)
      (wrap-json-body)
      (wrap-json-response)
      (wrap-contenttype :request "application/json")
      (wrap-defaults api-defaults)
      (wrap-with-logger)))

