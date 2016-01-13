(ns clj-emv.utils
  "Utilities for various purposes"
  (:use clj-emv.bit-ops))

(defn hex-to-num[hex]
  (read-string (str "0x" hex)))

(defn hexify[value]
  (format "%02X" value))

(defn hexify-list[values]
  (apply str (map hexify values)))

(defn string-to-bytes[hex]
  (javax.xml.bind.DatatypeConverter/parseHexBinary hex))

(defn bytes-to-string[bytes]
  (javax.xml.bind.DatatypeConverter/printHexBinary bytes))

(defn bytes-to-hex-string[bytes]
  (bytes-to-string (byte-array bytes)))

(defn bytes-to-num[bytes]
  (hex-to-num (bytes-to-hex-string bytes)))

(defn parse-hex-string[hex-byte-string]
  (map unsigned (string-to-bytes hex-byte-string)))

(defn bytes-to-ascii[bytes]
  (if (nil? bytes)
    "(n/a)"
    (String. (byte-array bytes) "ASCII")))
