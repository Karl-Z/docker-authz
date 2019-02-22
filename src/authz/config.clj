#_(ns authz.config
  (:use [authz.core]
        [clojure.set]))

(ns authz.core)

;;; data source definitions
;;
(defsource txtfile-api
  :type passwd
  :cache true
  :parameters {:path "resources/docker-api.txt"})


(defsource txtfile-users
  :type passwd
  :parameters {:path "resources/users.txt"})

(defsource txtfile-superusers
  :type passwd
  :parameters {:path "resources/users.txt" :match "admin-.*"})

(defsource txtfile-usergroups
  :type group
  :parameters {:path "resources/user-groups.txt"})

(defsource txtfile-supergroups
  :type group
  :parameters {:path "resources/user-groups.txt" :match "admin-.*"})

(defsource txtfile-hosts
  :type passwd
  :parameters {:path "resources/hosts.txt"})

(defsource txtfile-hostgroups
  :type group
  :parameters {:path "resources/host-groups.txt"})

(defsource txtfile-deploymentenvironments
  :type group
  :parameters {:path "resources/deployment-environments.txt"})

;;; validator definitions
;; validate one aspect of request
;; :path - input value from the path of request, same as get-in
;; :transform - a group of tuples of regexp and replacement
;; :validator - call the function with input value or transformed input value
;; :optional - ignore input and return true

(defrule valid-uri
  :path [:body "RequestUri"]
  :transform ["^/v\\d\\.\\d\\d" ""
              "\\?.*" ""
              "containers/[^/]*/" "containers/"]
  :validator txtfile-api)

(defrule valid-user
  :path [:body "User"]
  :validator txtfile-users)

(defrule super-user
  :path [:body "User"]
  :validator txtfile-superusers)

(defrule valid-usergroup
  :path [:body "UserGroup"]
  :validator txtfile-usergroups)

(defrule super-usergroup
  :path [:body "UserGroup"]
  :validator txtfile-supergroups)

;; some derived arguments are stored in json's "@" key
(defrule valid-host
  :path [:body "Host"]
  :validator txtfile-hosts)

(defrule valid-hostgroup
  :path [:body "HostGroup"]
  :validator txtfile-hostgroups)

;; lookup function for user group identification
(deflookup usergroups-lookup
  :dominion [txtfile-usergroups]
  :return name->group)

;; lookup host group 
(deflookup hostgroups-lookup
  :dominion [txtfile-hostgroups]
  :return name->group)

;; lookup deployment environment
(deflookup deploymentenvironments-lookup
  :dominion [txtfile-deploymentenvironments]
  :return name->group)

;; add callback function to predefined hooks
(add-hook wrap-usergroups-hook usergroups-lookup)
(add-hook wrap-hostgroups-hook hostgroups-lookup)
(add-hook wrap-deploymentenvironments-hook deploymentenvironments-lookup)

;; re-subset?: checking subset1 again subset2 which contains regexp that must
;;             match entry in subset1
(defrule repo-tags
  :path [:body "ResponseBody" "RepoTags"]
  :validator #(re-subset? % #{"docker.io/busybox.*"}))


(defrule post-method
  :path ["RequestMethod"]
  :validator #(= % "POST"))

(defrule have-labels
  :path [:body "Labels"]
  :validator #(re-subset? % #{"com\\.company\\.user-.*"}))

(defrule drop-caps
  :path [:body "HostConfig" "CapDrop"]
  :validator #(subset? #{"NET_BIND_SERVICE" "SETUID" "SETGID"} %))

(defrule have-caps
  :path [:body "HostConfig" "CapAdd"]
  :type :optional
  :validator #(subset? % #{"SYS_PTRACE"}))

(defrule allowed-network
  :path ["NetworkMode"]
  :type :optional
  :validator #{"bridge" "none"})

(defrule allowed-environments
  :path [:body "DeploymentEnvironment"]
  :validator #{"dev" "qa" "prod" "uat"})

(defrule denied-environments
  :path [:body "DeploymentEnvironment"]
  :validator #{"uat"})

(defrule allowed-mounts
  :path [:body "HostConfig" "Mounts"]
  :validator #(re-subset? % #{".*=/opt" ".*=/var/log" ".*=/user/local"}))

(defrule allowed-volumes
  :path [:body "Volumes"]
  :validator #(re-subset? % #{"com\\.company\\.user-.*"}))

(defpolicy default-policy
  :base #{"/v1.26"}
  :uri "/.*"
  :condition :all
  :rules [valid-uri valid-user valid-host valid-hostgroup])

(defpolicy deploy-environment-policy
  :base #{"/v1.26"}
  :uri "/.*"
  :rules [allowed-environments])

(defpolicy denied-deploy-environment-policy
  :base #{"/v1.26"}
  :uri "/.*"
  :condition :none
  :rules [denied-environments])

(defpolicy container-create
  :base #{"/v1.26"}
  :uri "/containers/create"
  :condition :some
  :rules [super-user super-usergroup])

(defpolicy build
  :base #{"/v1.26"}
  :uri "/build"
  :rules [super-user])

