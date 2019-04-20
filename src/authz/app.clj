(ns authz.app
  (:require [authz.core :refer :all])
  (:require [clojure.set :refer :all])
  (:require [clojure.tools.logging :as log])
  (:require [authz.utils :refer :all])
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
  (:require [authz.wrap-docker-api-base :refer :all])
  (:require [ring.middleware.defaults :refer :all])
  (:require [ring.middleware.json :refer :all])
  (:require [ring.middleware.logger :refer :all])
  (:require [environ.core :refer [env]])
  (:require [clojure.java.io :as io :refer [file]]))

;; Load config file, file name come from environment "docker.policy"
;; or "docker_policy", default is "resources/config/policy.clj"
(let [polfile (env :docker-authz-policy)]
  (if polfile
    (do
      (log/info "Loading policy file:" polfile)
      (reset! *config-directory*
              (.getCanonicalPath
               (.getParentFile
                (io/file polfile))))
      (load-file polfile))
    (throw (java.io.IOException. "Policy file not set, please set it in environment variable 'DOCKER_AUTHZ_POLICY'"))))

(def app
  (-> authz-routes
      (wrap-usergroup)
      (wrap-deploymentenvironment)
      (wrap-hostgroup)
      (wrap-host)
      (wrap-docker-api-base)
      (wrap-requesturi-parse)
      (wrap-requesturi-rewrite)
      (wrap-responsebody-decode)
      (wrap-requestbody-decode)
      (wrap-json-body)
      (wrap-json-response)
      (wrap-contenttype :request "application/json")
      (wrap-defaults api-defaults)
      (wrap-with-logger)))

