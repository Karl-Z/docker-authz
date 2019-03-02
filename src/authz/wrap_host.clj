(ns authz.wrap-host
  (:require [authz.core :refer :all])
  (:require [clojure.string :as str])
  (:require [ring.util.response :as response])
  (:require [clojure.tools.logging :as log])
  (:require [clj-dns.core :as dns]))


;; Reverse lookup ip-addr, if found, return DNS name
;; otherwise, return IP
(defn find-hostname
  "Find localhost's canonial name"
  [ipaddr]
  (try
    ;; remove ending dot
    (str/replace 
     (str/trim (dns/reverse-dns-lookup ipaddr))
     #"\.$" "")
    (catch java.net.UnknownHostException e
      ipaddr)))


;; lookup for host
(deflookup host-lookup
  :return find-hostname)

;; Middleware for adding peer host info
;; normally, it is the docker engine
(defwrapper wrap-host
  :hook wrap-host-hook
  :input-path [:remote-addr]
  :output-path [:body "Host"])

(add-hook wrap-host-hook host-lookup)
