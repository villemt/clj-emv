# clj-emv

EMV compliant terminal implementation in Clojure. Why? For learning EMV and Clojure language.

## What is this?

This is a partial and heavily work-in-progress EMV compliant implementation of the public EMV specifications in Clojure
http://www.emvco.com/specifications.aspx

The code implements the terminal side of the specification and required data processing (EMV 4.3 + Contactless). In order to use the code, get yourself an RFID reader and have fun with your personal payment card, at your own risk ;)

The work is purely based on public information and standards by EMVCo. Confidential information in any form, e.g. card scheme specific details that are not in public domain, are not included in this implementation.

The project is for learning purposes only (EMV + Clojure) and does not strive to become a working implementation of the full standard.

EMV Tags and CA Public Key listings under /resources are provided by [EFTlab Ltd.](https://www.eftlab.com.au) and used with permission.

## What does it do?

Currently supported (simplified implementation):
 * Simple text-based command-line UI
 * Smart card terminal selection (Contact/NFC)
 * Payment environment selection (PSE/PPSE)
 * Payment card selection (AID)
 * Initiation of payment processing (dummy PDOL)
 * Processing of AIP AFL
 * SDA based Issuer Public Key certificate verification and Issuer Public Key extraction
 * DDA based ICC Public Key Certificate verification and ICC Public Key extraction

Main missing features on high level
 * Terminal resident data based logic (e.g. proper PDOL creation)
 * Select of the application based on terminal resident AID list
 * Processing Restrictions
 * Cardholder Verification
 * Terminal Risk Management
 * Terminal Action Analysis
 * Card Action Analysis

## Where can I learn this?

* http://www.emvco.com
* http://www.openscdp.org
* https://www.eftlab.co.uk
* http://www.emvlab.org
* http://www.cardwerk.com

## How can I use this?

The goal is to support both library-oriented usage patterns in addition to being a standalone application with a text-based UI.

```
lein run
```

## It doesn't work, should I complain?

Yes, this is a very preliminary implementation but feedback is welcome.

## License

Copyright © 2016 Ville-Matti Toivonen, sponsored by [Futurice Open Source Program](http://spiceprogram.org/)

Distributed under the MIT License.
