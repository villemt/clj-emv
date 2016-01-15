(ns clj-emv.date
  "Date utilities"

  (:require [clj-time.core :as t])
  (:require [clj-time.format :as f])
  (:require [clj-time.coerce :as c])
  (:require [clj-time.local :as l]))

(defn parse-date[string]
  (def date-formatter (f/formatter "YYMMdd"))
  (f/parse date-formatter string))

(defn parse-certificate-expiration-date[string]
  (def date-formatter (f/formatter "MMYY"))
  (f/parse date-formatter string))

(defn print-date[date]
  (def date-formatter (f/formatter "YYYY-MM-dd"))
  (f/unparse date-formatter (c/to-date-time date)))
