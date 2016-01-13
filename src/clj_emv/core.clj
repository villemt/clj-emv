(ns clj-emv.core
  (:gen-class)
  (:use clj-emv.pcsc)
  (:use clj-emv.bit-ops)
  (:use clj-emv.crypto)
  (:use clj-emv.utils)
  (:use clj-emv.tags)
  (:use clj-emv.file)
  (:use clj-emv.date)
  (:use clj-emv.sda)
  (:use clj-emv.dda)
  (:require [clj-emv.ui :as ui])
  (:require [clj-time.core :as t])
  (:require [clj-time.format :as f])
  (:require [clj-time.coerce :as c])
  (:require [clj-time.local :as l])
  (:require [clojure.string :as str]))

;;
;; MAIN APPLICATION FLOW
;;
(defn -main[& args]
  (let [terminal (ui/select-terminal (get-terminals))
        card (if (:is-card-present terminal) (get-card terminal) (ui/exit-program "Card not found"))
        channel (get-channel card)
        environment (ui/select-environment)
        application (ui/select-application-in-environment channel environment)
        pdol (ui/select-single-application channel application)
        [aip aip-bytes afls] (ui/initiate-application-process channel pdol)
        tags (ui/read-afl-tags channel afls)

        ; Issuer Public Key information
        [issuer-public-key-certificate nca] (get-issuer-public-key-certificate application tags)
        [issuer-public-key-modulus issuer-public-key-exponent ni] (get-validated-issuer-public-key-modulus issuer-public-key-certificate nca tags false)

        ; ICC Public Key information
        icc-public-key-certificate  (get-icc-public-key-certificate issuer-public-key-modulus issuer-public-key-exponent ni tags)
        [icc-public-key-modulus icc-public-key-exponent nic] (get-validated-icc-public-key-modulus icc-public-key-certificate ni tags aip-bytes false)

        ; SDA
        data-authentication-code (if (:sda-supported aip)
          (perform-sda issuer-public-key-modulus issuer-public-key-exponent ni tags)
          nil)

        ; DDA
        result (if (:dda-supported aip)
          (perform-dda channel icc-public-key-modulus icc-public-key-exponent nic)
          nil)
        ]))
