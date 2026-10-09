# wifi-lan-scanner

Piccolo strumento in C per vedere chi e' collegato alla **propria** rete
Wi-Fi/LAN, da terminale. Funziona su macOS e Linux, nessuna dipendenza
esterna oltre la libreria standard del sistema.

## Cosa fa

- Scansiona la subnet `/24` della tua rete provando connessioni TCP su
  alcune porte comuni (configurabili).
- Legge la tabella ARP del sistema per ottenere gli indirizzi MAC.
- Prova a risolvere il nome host di ogni dispositivo.
- Puoi tenere un elenco di dispositivi "noti" (file di testo con
  `MAC nome`): chi non e' nell'elenco viene segnalato come sconosciuto.
- Modalita' monitor: ripete la scansione nel tempo e segnala quando un
  dispositivo entra, esce, o cambia MAC (utile anche contro lo spoofing).
- Esportazione dei risultati in CSV.

## Cosa NON fa (volutamente)

Non disconnette, blocca o interferisce in alcun modo con altri
dispositivi: niente ARP spoofing, niente deautenticazione Wi-Fi. E'
pensato solo per **osservare** la propria rete. Per bloccare un
dispositivo, usa il pannello di amministrazione del tuo router (MAC
filtering), che e' il punto corretto per farlo.

## Compilazione

```bash
cc -O2 -Wall -Wextra -o wifi_check src/wifi_check.c
```

Funziona con `gcc` o `clang`. Su macOS, se richiesto, installa prima gli
strumenti da riga di comando con `xcode-select --install`.

## Uso

```bash
./wifi_check -h
```

Esempi:

```bash
# scansione singola della rete corrente
./wifi_check

# registra i dispositivi attuali come "noti" in un file
./wifi_check -k noti.txt -a
# poi apri noti.txt e assegna un nome a ciascuna riga

# monitor continuo: segnala chi entra/esce ed eventuali sconosciuti
./wifi_check -k noti.txt -w 30

# salva ogni scansione in un CSV
./wifi_check -o log.csv
```

Su macOS, dalla versione Sequoia in poi, il Terminale potrebbe dover
chiedere l'accesso alla rete locale: Impostazioni di Sistema > Privacy
e sicurezza > Rete locale.

## Note

- Non serve `sudo`.
- Un dispositivo con firewall rigido o in sospensione puo' non comparire
  nella scansione TCP; la tabella ARP aiuta a recuperarne alcuni.
- iPhone e Android usano di default un indirizzo MAC privato/casuale per
  rete, che puo' cambiare periodicamente: per un riconoscimento stabile,
  disattiva "Indirizzo privato" per la tua rete di casa nelle
  impostazioni Wi-Fi del telefono.
- Usalo solo sulla tua rete o su reti per cui hai l'autorizzazione.

## Licenza

MIT, vedi [LICENSE](LICENSE).
