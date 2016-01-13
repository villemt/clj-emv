(ns clj-emv.bit-ops
  "Helpers for handling bitwise operations and fields")

(defn unsigned[signed]
  (if (< signed 0) (+ signed 256) signed))

(defn bit-on-at[position]
  (bit-shift-left 1 (- position 1)))

(defn bits-on-at[positions]
  (apply + (map bit-on-at positions)))

(defn bit-on-at?[position value]
  (let [ref (bit-on-at position)]
    (= ref (bit-and ref value))))

(defn bits-on-at?[positions value]
  (every? true? (map #(bit-on-at? % value) positions)))

(defn bit-off-at?[position value]
  (not (bit-on-at? position value)))

(defn bits-off-at?[positions value]
  (every? true? (map #(bit-off-at? % value) positions)))

(defn equals-masked[mask byte1 byte2]
  (let [masked-byte1 (bit-and mask byte1)
        masked-byte2 (bit-and mask byte2)]
    (= masked-byte1 masked-byte2)))

(defn combine-bytes[byte1 byte2]
  (+ (bit-shift-left byte1 8) byte2))
