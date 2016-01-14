(ns clj-emv.restrictions
  "Processing restrictions"
  (:require [clj-emv.terminal :as terminal]))


(defn check-application-version-number[application-version-number]
  (let [is-available (not (nil? application-version-number))
        is-different (not (= terminal/TERMINAL_APPLICATION_VERSION_NUMBER application-version-number))
        is-invalid (and is-available is-different)]
    {:icc-and-terminal-have-different-application-version is-invalid}))
