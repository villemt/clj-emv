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
  (:require [clj-emv.restrictions :as restrictions])
  (:require [clj-emv.ui :as ui])
  (:require [clj-emv.cvm :as cvm])
  (:require [clj-time.core :as t])
  (:require [clj-time.format :as f])
  (:require [clj-time.coerce :as c])
  (:require [clj-time.local :as l])
  (:require [clojure.string :as str])
  (:require [clojure.pprint :as pprint]))

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

        ; Processing Restrictions
        application-version-number (tag-value-as-number (filter-tag tags APPLICATION_VERSION_NUMBER))
        application-usage-control (apply application-usage-control-from-bytes (:value (filter-tag tags APPLICATION_USAGE_CONTROL)))
        issuer-country-code (filter-tag tags ISSUER_COUNTRY_CODE)
        application-effective-date (tag-value-as-date (filter-tag tags APPLICATION_EFFECTIVE_DATE))
        application-expiration-date (tag-value-as-date (filter-tag tags APPLICATION_EXPIRATION_DATE))
        tvr-restrictions (ui/check-processing-restrictions application-version-number application-usage-control
         issuer-country-code application-effective-date application-expiration-date)

        ; Cardholder Verification
        cvm-list-tag (filter-tag tags CARDHOLDER_VERIFICATION_METHOD_LIST)
        currency-tag (filter-tag tags APPLICATION_CURRENCY_CODE)
        [tvr-cvm tsi-cvm] (ui/perform-cvm cvm-list-tag currency-tag)

        ; Terminal Risk Management
        lower-consecutive-offline-limit-tag (filter-tag tags LOWER_CONSECUTIVE_OFFLINE_LIMIT)
        upper-consecutive-offline-limit-tag (filter-tag tags UPPER_CONSECUTIVE_OFFLINE_LIMIT)
        atc (get-data-command channel 0x9F 0x36)
        last-online-atc-register (get-data-command channel 0x9F 0x13)

        [tvr-risk-mgmt tsi-risk-mgmt] (ui/perform-terminal-risk-management
          lower-consecutive-offline-limit-tag upper-consecutive-offline-limit-tag atc last-online-atc-register)

        ; Create final TVR
        tvr (merge tvr-restrictions tvr-cvm tvr-risk-mgmt)

        ; Terminal Action Analysis
        action-code-default-tag (filter-tag tags ISSUER_ACTION_CODE_DEFAULT)
        action-code-denial-tag (filter-tag tags ISSUER_ACTION_CODE_DENIAL)
        action-code-online-tag (filter-tag tags ISSUER_ACTION_CODE_ONLINE)
        cdol1-tag (filter-tag tags CARD_RISK_MANAGEMENT_DATA_OBJECT_LIST_1)
        dynamic-number-response (get-dynamic-number-command channel)
        result (ui/perform-terminal-action-analysis
          channel
          tvr
          action-code-default-tag
          action-code-denial-tag
          action-code-online-tag
          cdol1-tag
          dynamic-number-response)

        ; Create final TSI
        tsi (merge tsi-cvm tsi-risk-mgmt)
        ]
  (println "TVR:")
  (pprint/pprint tvr)

  (println "TSI:")
  (pprint/pprint tsi)))
