(ns authz.core-test
  (:require [clojure.test :refer :all])
  (:require [authz.core :refer [defsource defrule deflookup defpolicy defwrapper
                                wrap-usergroups-hook wrap-hostgroups-hook
                                add-hook re-subset? name->group]])
  (:require [clojure.string :as str]))


;; ------------ init ---------------
(def literal identity)
(defsource users
  :type literal
  :parameters #{"user1", "user2", "user3"})


(defsource usergroups
  :type literal
  :parameters {"ugrp1" #{"user1", "user2"} "ugrp2" #{"user2", "user3"}}
  )

(defsource hosts
  :type literal
  :parameters #{"host1", "host2", "host3", "host4"})

(defsource hostgroups
  :type literal
  :parameters {"hgrp1" #{"host1", "host2"}, "hgrp2" #{"host2", "host3"}, "hgrp3" #{"host4"}})

(defrule valid-user
  :path ["User"]
  :validator users)

(deflookup usergroups-lookup
  :dominion [usergroups]
  :return name->group)

(deflookup hostgroups-lookup
  :dominion [hostgroups]
  :return name->group)

(add-hook wrap-usergroups-hook usergroups-lookup)
(add-hook wrap-hostgroups-hook hostgroups-lookup)

;; ------------------ tests ---------------
(deftest defsource-test
  (is (= #{"user1" "user2" "user3"} (users))))

(deftest defrule-test
  (is (boolean (valid-user {"User" "user1"})))
  (is (not (boolean (valid-user {"User" "user4"})))))


(deftest re-subset?-test
  (is (re-subset? #{"aa" "bb"} #{#"a." #"b."}))
  (is (not (re-subset? #{"aa" "bb" "cc"} #{#"a." #"b."})))
  )

(deftest deflookup-test
  (is (= "ugrp1" (usergroups-lookup "user1")))
  )

(deftest add-hook-test
  (is (= usergroups-lookup @wrap-usergroups-hook) )
  (is (= hostgroups-lookup @wrap-hostgroups-hook) ))


(run-tests)
