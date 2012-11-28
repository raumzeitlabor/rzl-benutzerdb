Hier finden sich alle Programme, die mit der Benutzerdatenbank arbeiten.

Übersicht
=========

* **BenutzerDB** enthält das Web-Frontend, deployed auf blackbox.rzl
* **pin-validator** enthält das Script, welches zwischen Hausbus und BenutzerDB vermittelt (bestätigt die Gültigkeit einer am Pinpad eingegebenen PIN)
* **pin-sync** enthält das Script, welches PINs auf den Pinpad-Controller synchronisiert (zwecks schneller Verifikation/Ausfallsicherheit).
* **ssh-pubkey-sync** enthält das Script, welches Pubkeys aus der BenutzerDB zieht und abspeichert
* **mod-auth-mysql** enthält die Sources zu dem Debianpaket des gepatchten mod-auth-mysql Modules (mit Support für Crypt::SaltedHash Hashes)
