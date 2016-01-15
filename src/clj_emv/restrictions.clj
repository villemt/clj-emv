(ns clj-emv.restrictions
  "Processing restrictions"
  (:require [clj-emv.terminal :as terminal])
  (:require [clj-time.core :as t])
  (:require [clj-time.coerce :as c]))

(defn check-application-version-number[application-version-number]
  (let [is-available (not (nil? application-version-number))
        is-different (not (= terminal/TERMINAL_APPLICATION_VERSION_NUMBER application-version-number))
        is-invalid (and is-available is-different)]
    {:icc-and-terminal-have-different-application-version is-invalid}))

(defn check-application-usage-control[application-usage-control issuer-country-code]
  ;TODO: validation
)

(defn check-application-dates[application-effective-date application-expiration-date]
  (let [today (t/today)
        effective-date-available (not (nil? application-expiration-date))
        expiration-date-available (not (nil? application-expiration-date))
        effective-date-not-passed (and effective-date-available (t/before? today application-effective-date))
        expiration-date-passed (and expiration-date-available (t/before? application-expiration-date today))]
    {:application-not-yet-effective effective-date-not-passed
     :expired-application expiration-date-passed}))
