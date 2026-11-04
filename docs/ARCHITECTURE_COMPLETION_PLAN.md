Stato corrente — Wave 3 M4.2 propagazione DAG/scheme ordering e M5 isolamento config/environment/secrets integrati — 2026-10-25.
Tutti M0–M8 restano richiesti; firma differita. Installata CLI 1653a8d8b3f32b1df44d41a2ba83ba9f81dde96fb84a75e44812a0cb7bdb1be0,
backup b17 (previous-installed-native-b17.exe), host 6040c677 e Unicorn 861d6c05 invariati.
Suite 88/88 PASS in 190.90s (build+suite 297.553s); 656 hash sorgenti invariati, dirty
ereditato preservato in due commit focalizzati: 035c702 (M4.2 propagazione librerie
statiche figlie in pkg_res.static_libraries con deduplicazione linker, -force_load
ristretto ad .app, prevenzione falsi cicli scheme_entry) e 3ad5422 (M5 isolamento
dispatch CLI read-only in main.cpp e Config::BuildEnvironmentVariables pura/idempotente).
CLI reale verify-selected-cli.py: package (73.593s), aggregate (24.014s) e static library
(7.768s) producono SelectedProof-unsigned.ipa (SHA
7d0aafbe7d0d47a6ba7a39062b426caa942f5f309b9c3f0b26afe5a37e4c925c, 51552 byte MH_EXECUTE
ARM64). Nextcloud preflight metadata-only 0/2.640s (1204 riusi/0 copie); bootstrap
installato 0/2.664s + 0/2.552s (1383 file e 71 input Apple invariati). Prossima Wave 4
(già progettata in worker-quality-and-wave4-audit.json): FRAMEWORK_SEARCH_PATHS/
LIBRARY_SEARCH_PATHS + ricorsione /** senza mutazioni disco + PBXCopyFilesBuildPhase, e
rilevamento Mach-O in-process per IsDynamicFramework + preservazione EXECUTABLE_NAME in
PackagerSigner. Case autorevole: 20261025-dag-propagation-and-config-isolation e
CURRENT_CHECKPOINT.md.

Stato corrente — Wave 2 M4.2 conditional PBX build settings e chiusura transitiva SwiftPM integrati — 2026-10-25.
Tutti M0–M8 restano richiesti; firma differita. Installata CLI b176af87a776a622da957b93e073c9a38976566ee1565c4cd69276bd07ce3c1b,
backup 7ff (previous-installed-native-7ff.exe), host 6040c677 e Unicorn 861d6c05 invariati.
Suite 88/88 PASS in 166.80s (build+suite 245.880s); 656 hash sorgenti invariati, dirty
ereditato preservato in due commit focalizzati: c95c01f (M4.2 conditional PBX build
settings inline e chiusura transitiva SwiftPM) e 29e84a5 (M4.2/M4.3 proiezione workspace
delle radici subproject e package locali transitivi). CLI reale verify-selected-cli.py:
package (56.608s), aggregate (20.758s) e static library (5.676s) verificano
PRODUCT_NAME[sdk=iphoneos*][arch=arm64]=SelectedProof sopra SimulatorIgnored e
risolvono transitivamente SelectionLeaf tramite SECOND -> GENERATE
(SelectedProof-unsigned.ipa SHA 41f4be6e13450f44f99d0ff92578cd6718ee058aff30c61030bf4f569a0b0887,
51552 byte MH_EXECUTE ARM64). Nextcloud preflight metadata-only 0/2.323s (1204 riusi/0 copie);
bootstrap installato 0/2.271s + 0/1.950s (1383 file e 71 input Apple invariati).
Prossima Wave 3: propagazione prodotti target figli nel DAG (librerie statiche in
pkg_res.static_libraries, -force_load ristretto ad .app, prevenzione falsi cicli
scheme_entry) e isolamento M5 di config/environment/secrets prima del bootstrap mutabile
in main.cpp. Case autorevole: 20261025-conditional-settings-and-package-closure e
CURRENT_CHECKPOINT.md.

Stato corrente — Wave 1 M4.2 identità prodotto/modulo/bundle e M4.3 pruner bounded/cancellable integrati — 2026-10-25.
Tutti M0–M8 restano richiesti; firma differita. Installata CLI 7ff2625b4ea3319c64407f7829e850201fa60e5b78543ec2e7f806e5bd506936,
backup d15 (previous-installed-native-d15.exe), host 6040c677 e Unicorn 861d6c05 invariati.
Suite 88/88 PASS in 178.31s (build+suite 214.007s); 656 hash sorgenti invariati, dirty
ereditato preservato in due commit focalizzati: 757a100 (M4.2 identità Xcode target/product/
module/display/executable) e 69d44dc (M4.3 retention bounded/cancellable nel pruner esistente).
CLI reale verify-selected-cli.py: inspect --json riporta project_name=Chosen, product_name=
SelectedProof, module_name=SelectedProof, display_name=SelectedProof; package emette
SelectedProof-unsigned.ipa (SHA e3e9b7856a838404fd4ca31c531ab5dbbdced8ec174dfc863d409d5c408e864a)
con Payload/SelectedProof.app/SelectedProof (51552 byte MH_EXECUTE ARM64) e Info.plist
CFBundleName/CFBundleExecutable/CFBundleDisplayName=SelectedProof. Nextcloud preflight
metadata-only 0/2.524s (1204 riusi/0 copie); bootstrap installato 0/2.003s + 0/2.157s
(1383 file e 71 input Apple invariati). Prossima Wave 2: conditional PBX build settings
inline ([sdk=*]/[arch=*]/[config=*]/[variant=*]) e chiusura transitiva SwiftPM lungo
PBXTargetDependency (inclusi subproject .xcodeproj). Case autorevole:
20261025-product-identity-and-bounded-prune e CURRENT_CHECKPOINT.md.

Stato corrente — selezione Xcode esplicita integrata — 2026-10-25.
Tutti M0–M8 restano richiesti; firma differita. Installata CLId15e2543fd33487d06fc8c1b8552b318b0040ec7bfee1b74c21dd3328ed75e55,
backup3ed, host604/Unicorn861 invariati. Suite88/88 PASS182.29s, build+suite258.052s;
656 hash sorgenti invariati, dirty ereditato preservato in tre commit mirati:
6e8c901 parser/scopo azioni/config;4e02933 metadata e view;acf60ec consumer nativi.

Richiesta condivisa scheme/UUID qualificato/config canonica: parser XML bounded,
Git120000 originale, SHA metadata/xcconfig e assenze opzionali verificati nella view.
Un workspace r1 conserva lease e sorgenti; prodotti/intermedi separati per selezione
ed owner+UUID. SwiftPM consuma il root selezionato; DAG non reinferisce altri scheme.
Build-purpose filtra membership, non esegue test/run/archive. Build nonapp restituisce
il suo artefatto; package richiede applicazione, nessuna IPA inventata per aggregati.
CLI reale seleziona SECOND e ignora FIRST disabilitato con package mancante:
Swift6.4.1/SDK27 arm64-ios18 -> MachO MH_EXECUTE51552bytes + IPA unsigned in78.259s.
Aggregato0/7.377s; libreria statica0/6.922s, un vero MH_OBJECT ARM64 nell'archivio.
Stessa view w/r1-ca100fc85b026686,0 copie nei due run successivi; sorgenti e71Apple
invariati, output generati ripristinati, progress succeeded e tracce senza WSL/Darling.
Bootstrap installato0/2.906+2.915s:1383 file/ID/mtime invariati, zero partial aggiuntivi.

D8/080 suite verdi mantenute con i loro hash. Il vero inspect080 falliva per alias
.OPENFRUIT/.openfruit: controllo Win32 + ID prova stessa directory. D15 ammette solo
prefisso canonicalmente equivalente e preserva ordine link/..; test uppercase e
sibling case-sensitive eseguiti, nessuno SKIP. Snapshot concorrenti non atomici.
Nextcloud metadata preflight0/7.492s:1204 riusi/0 copie; config, prodotti, contesti e
originali invariati. Nessuna nuova compilazione Nextcloud o correzione bug SIL.
Review agenti sul gruppo senza ulteriori P1/P2; non quality finale M0–M8.
Caseautorevole20261024-explicit-scheme-selection e CURRENT_CHECKPOINT.md.

Prossimo difetto verificato M4.2: PRODUCT_NAME=SelectedProof in inspect, ma IPA
Chosen.app/Chosen dal TARGET_NAME; correggere identita prodotto/modulo/executable/
display nel dominio, AppBuilder e packaging, usando le fonti originali Swift Build.
Restano closure package dei figli/root nel DAG, conditional PBX, retention globale
bounded/cancellable, servizi/adapter, matrice applicazioni e release nativa.
Le sezioni seguenti sono storiche.

Stato corrente — retention probe installata e team storage — 2026-10-22.
CLI9b4e295399e660e3d995ac373ee7474ce7a3062069104a706c8711ce73c188f5,
backupc30; host/Unicorn invariati. Suite76/76 PASS168.79s, focused1/1 PASS0.24s.
Tre probe usano lease/pruner esistenti: cleanup successi dopo chiusura lettori,
fallimenti con log, raccolta differita7giorni/512MiB soft solo payload partecipanti.
Attivi/legacy protetti; piccoli marker persistono, namespace non totalmente bounded.
CLI reale SDK/LLVM/asset compiler exit0/63.614s senza nuovi payload probe; ramo Swift
development non esercitato. Bootstrap installato exit0/2.344s e0/1.952s,1383 file
invariati, zero nuovi partial,71 originali Apple immutati. Review scoped senza issue
azionabili; non e la quality finale. Team nativo separato: acquisizione verificata,
inventario/riferimenti storage, quality probe; Main integra/builda/installa.
M4.3 retention globale e M0–M8 restano aperti; firma differita. Nextcloud SIL resta
irrisolto, nessun full rerun invariato. CURRENT_CHECKPOINT.md autorevole.
Le sezioni seguenti sono storiche.

Stato corrente — lifetime runtime e gate CLI senza XIP — 2026-10-22.
M0–M8 restano richiesti; firma differita. CLIc30e2b617e2eac5cdd54ab0feac59265b38cc602890356f7e2a9a7a8b18b93a1 installata, backup34a, host/Unicorn invariati.
Suite75/75 PASS176.12s; focused2/2 PASS5.48s. ArtifactLease shared reader sullo
stesso lock, writer esclusi, ownership fino a copie del risultato package e linker
app. Handoff writer->reader con revalidazione completa, nessun upgrade con reader
attivi. Review ha identificato/corretto perdita lease durante discovery e writerwait
su output già bound. Test concorrenza/crash/cancel e package originale servizi nativi
con sorgenti owned invariati PASS57.708s.
CLI reale package senza XIP disponibile: exit0, package+app riusano runtime18 bound,
IPA unsigned con MH_EXECUTE ARM64 verificato.48 launch journal senza WSL/Darling.
Archivio ripristinato con identità/hash invariati,71 originali Apple immutati.
Bootstrap installato exit0/2.078s e0/2.226s,1383 file managed invariati, zero partial.
Il gate non certifica altri target o repair senza sorgenti: sdk-downloads protetto,
retention typed/reference-aware M4.3 e lifecycle completo restano aperti.
Nextcloud resta sul bug SIL initaccessor, senza compiler corretto verificato,
patch upstream, bypass o nuovo full rerun invariato. Quality finale intero obiettivo
ancora da fare, non sostituita dalla review di componente. CURRENT_CHECKPOINT.md
e prove candidate-bound sono autorevoli.
Le sezioni seguenti sono storiche.

Il precedente CLI40d910b1, host6040c677:71/71 PASS80.70s;34/34 diagnostici. App owned con
package sibling, plugin/tool Windows reale e sorgente generato, State originale
nel package ARM64, archivio e IPA non firmata: exit0 in401.659s, input e71
percorsi Apple invariati. Ownership attraversa API esistenti senza riscrivere
manifest. Il discriminante lifecycle resolver Git/artifact è completato; Nextcloud
UD2 resta aperto. Tutti M0–M8 richiesti, firma differita, nessuna percentuale
globale o qualita finale dichiarata. CURRENT_CHECKPOINT.md autorevole.
Le sezioni seguenti sono storiche.

Stato corrente — provider originale integrato — 2026-10-18.
Installato successivo CLI746d5de7, stesso host:71/71 PASS74.24s,34/34 diagnostici.
Proiezione dei sibling Xcode corretta e verificata nel consumer reale: grafo
risolto, input invariati; nuovo arresto54.690s nel source workspace SwiftPM che
rifiuta state=fileSystem. Prossimo contratto: trasferire ownership delle viste
locali indipendenti al consumer SwiftPM, senza riscrivere manifest upstream.
Pagina rigenerata:822righe,64scope,19verificati su prove storiche candidate-bound.

Prova produzione State del candidato precedente:
CLI d3c8e007 / host6040c677:71/71 test PASS100.39s. Percorso nativo
automatico SDK27/Swift6.4: vera @State Int=0, oggetto ARM64 e IPA owned
non firmata, exit0 in147.268s,71 percorsi originali invariati. Nessuna
sostituzione macro o WSL/Darling. Restano tutti i requisiti M0–M8; firma
differita. Prossimo contratto: proiezione dei package Xcode locali sibling
per verificare anche plugin build-tool Windows. Nextcloud UD2 resolver
ancora aperto; nessuna compatibilita globale dichiarata. Prove e gate in
CURRENT_CHECKPOINT.md. Le sezioni seguenti sono storiche.

Stato corrente — consumer compilatore State originale verificato — 2026-10-17.
Candidato CLI89423e08 invariato; host87726cf6 installato: terminazione protocollo
zero corretta (baseline exit2,candidato exit0),69/69 test PASS89.43s.
Vero compilatore WindowsSwift6.4+SDK27,arm64-ios17: typecheck @State exit0 con
cinque espansioni originali (peer/accessor e tre accessor di supporto),69 hash
host invariati. Solo libraryPath è tradotto in un controllo diagnostico; nessuna
espansione sostitutiva. Mapping/receipt gestiti e propagazione produzione restano
da integrare nell'host esistente. Nessun oggetto iOS,app o tutti i ruoli dimostrati.
M0–M8 restano integralmente richiesti,firma differita,qualità finale non ancora
ammessa. CURRENT_CHECKPOINT.md e prove20261017-compiler-provider autorevoli.

Stato storico — pipe/runqueue e NOFILE verificati — 2026-10-17.
Candidato 89423e08:69/69 test nativi PASS79.63s; originali invariati.
Sessione originale interattiva: capability8, load e due accessor StateMacro con
pause2.1s,4park/4wake,EOF/exit0. Le letture pendenti usano il runqueue esistente
e conservano la descrizione originale; test ABI/errori/deadline/cancellazione.
NOFILE rispetta slot liberi sotto il limite con descriptor alti già aperti.
Restano peer race/signal scope,provider gestito/integrato in swiftc e tutti i ruoli
necessari della macro. Nextcloud resta fermo nel resolver Swift6.4/libdispatch UD2,
causa da verificare; nessun nuovo rerun invariato. M0–M8 e qualità finale restano
richiesti; firma differita. Nessun50ms snapshot o compatibilità globale dichiarata.
CURRENT_CHECKPOINT.md e prove candidate-bound restano autorevoli.

Stato storico — precedente checkpoint task-PAC/task_info:
Stato corrente — policy task-PAC verificata; nuovo gruppo task_info — 2026-10-16.
Candidato ca124b6f installato:67/67 PASS77.70s,34 diagnostici/web e9 scanner PASS.
Main ARM64 seleziona NOJOP prima dei fixup: IA/DA/DB no-op, IB resta protetto;
conversioni raw, context/reuse e ABI ARM64e-v0 hanno consumer reali. Originale
SDK27 invariato supera il precedente errore ObjC e si arresta su Mach-47,
task_info3405 flavor15/count8. Nuovo gruppo identità/token audit assegnato al
subagent IPC, senza risposte fittizie. StateMacro e protocollo originale ancora
non verificati. Ledger60scope, catalogo818righe; policy parziale per ABI-v1,
eccezioni plugin-host e fixup B-key non supportati. Tutti M0–M8 restano nel piano,
firma differita; qualità finale soltanto al completamento reale. Checkpoint
autorevole: CURRENT_CHECKPOINT.md. Le note seguenti sono storiche.

Stato corrente — minimo pthread consumato dall'originale — 2026-10-15.
Candidato59edec76 installato:67/67 PASS80.69s,34 diagnostici/web e9 scanner PASS.
SET_SELF, worker policy e scheduling CPU misurato ora alimentano provider reali;
registro/copyout ritorna0x4000001e con ABI verificata. OriginaleSDK27 invariato
superaBSD366 e si ferma su PAC inlibobjc.A.dylib0x18041a9ec,BRK0xc472 dopoAUTDA
con discriminator0xb5ab. Audit: superclass class+8; mainARM64subtype0 richiedeNOJOP IA/DA/DB, maCPUabilitatutte. Fix/testABI/cache da eseguire; nessuna espansione
StateMacro ancora.59scope,817righecatalogo,12scopeverificati conlivelli espliciti.
Prossimo gruppo policyJOPperABI ePAC Objective-C, senza bypass/fakecode; schedulercompleto,
transport/State e tuttiM0–M8 restano richiesti. Firma differita, reviewqualitàfinale
soloallacompletezza reale. CURRENT_CHECKPOINT.md è autorevole; stati seguenti storici.

Stato corrente — gruppo workqueue nativo — 2026-10-15.
Candidato5cfdabca installato:67/67 test nativi PASS63.39s,34 diagnostici/web e9
scanner PASS;301 sorgenti congelati. BSD367/368 ora creano/ammettono veri worker,
parcheggiano e riusano contesti ARM64 conservando FP/TLS, con pile protette e
port/task reali. Prove su guest owned; originale SDK27 invariato si ferma ancora
BSD366 unsupported_pthread_capabilities, zero worker originali e nessuna espansione
StateMacro. Ledger54 scope, lifecycle workqueue resta partial: limiti/redrive/pressione
non verificati completamente. Prossimo gruppo SET_SELF/policy/voucher prima di
pubblicare capability. CURRENT_CHECKPOINT.md descrive fonti e limiti attuali.
M0–M8 e review qualità finale restano integralmente richiesti; firma differita.
I paragrafi di stato seguenti sono storici, non nuovi criteri di completamento.

Stato corrente — StateMacro originale su Windows — 2026-10-15.
Obiettivo attivo: vera espansione SwiftUIMacros.StateMacro senza WSL/Darling.
Originali SDK27/Xcode27A266a abbinati e immutati; rebasehigh8 corretto.
Candidato6783b242b546f23773449c76d17c0e313d3d82b5071a325f981f27ed7af09c56,66/66 test nativi PASS.
Registrazione pthread, copyout negoziato e priorità CPU reali verificati;
conversione PAC non bloccante corretta dopo revisione. Preparazione upcall
workqueue testata; lifecycle e feature mask ancora incompleti. Originale fermo
a BSD366 prima delle capability; nessuna macro/handshake riusciti.
Ledger50 scope espliciti e pagina diagnostica aggiornati; nessuna percentuale
globale. M0–M8 e revisione qualità finale restano richiesti; firma differita.
CURRENT_CHECKPOINT.md e prove candidate-bound sono autorevoli.
I preludi seguenti sono storici e non sostituiscono i requisiti del piano.

Stato storico — integrazione non-Darwin — 2026-10-13.
Loader/runtime Darwin sospeso su richiesta; firma differita. CLI6435db07...1d542
compilata/installata con snapshot400 file e bundle host asset36 file. Suite65/65
PASS85.26s; prove SDK/link del4d restano legate al relativo candidato;
fallimenti intermittenti Darwin del precedente8c conservati, non risolti da questo
PASS. Nessuna prova release o esecuzione device.
M4.1: proiezione prima del grafo, lease resolver e consumatori sullo scratch
esterno; gate CLI alias file/directory->compile iOS->link->IPA unsigned PASS,
originali Git invariati,53 processi/zeroWSL. M5/M6.3: BOM gestito in memoria,
contesto BUILD_DIR propagato prima dell'espansione; gate shell producer->consumer
PASS dentro workspace,36 processi/zeroWSL. M2: anchor/backdeploy Swift sintetici
rimossi; availability LLVM reale con cache fingerprint/lease/pubblicazione;
206 header verificati su compilatore reale. M7: diagnostiche OpenIB originali e
intent mancanti propagati/fail-closed; tre gate negativi CLI PASS,101 processi/
zeroWSL. Nessuna percentuale globale o prova device/firma/plugin originale nuova.
Nove .a originali SDK27 estratti in staging con firme/checksum: otto iOS,
SwiftDirectRuntime dichiara macos nonostante la directory iphoneos: non eleggibile
per iOS. Acquisizione/selezione/pubblicazione nativa automatica ora integrata con
pairingSDK/XIP, hashLLVM/ABI/deployment, lease/cancel e receipt finale. Otto archivi
immutati verificati indipendentemente9/9. Gate CLI Observable originale e libreria
Compatibility56+Core e Swift concurrency15 PASS; MissingStrong resta FAIL;
deployment child15/parent17.4 verificato in argv/header Mach-O. Cinque journal,
140 processi/zeroWSL; IPA unsigned/CRC/ARM64/input verificati. Child14 compilato
fuori minimoSDK27 è solo prova propagazione, validazione child resta da completare.
Il14 non è supportato daSDK27(min15); l'esclusione
SDK26.5(min12) dalla selezione14 resta da spiegare, non aggirata. M4.3 cache
persistente verificata, parity risorse/tool, device/release e
restanti gate M0–M8 incompleti. Macro StateMacro Nextcloud ancora bloccata; prove
Darwin/dashboard restano candidate695-bound. CURRENT_CHECKPOINT.md è autorevole;
i preludi seguenti sono storici e non sostituiscono i requisiti del piano.

M6.3/M7 SVG/asset: provider resvgWindows0.45.1 acquisito dalla CLI nativa con pin
osservato OPENFRUIT (nessun digest publisher disponibile), PE/version/render13x7,
lease/cancel e import transazionale. Eliminati fallbackWSL/PATH e skip silenziosi
di cataloghi/asset set; DLLSwift importate solo in bundle funzionalmente verificato,
nessuna selezione casuale o installazionePowerShell. Wrapper originaleOPENFRUIT
compila con AssetKit/h/swift-png invariati, metadata determina baseURLSVG; stream
concorrenti bounded e warningrenderer diventano errori. Positive6435: IPA unsigned
CRC/ARM64, CARparseindipendente con3rasterLZFSE13x7/26x14/39x21, SVGoriginale e
coloreRGBA atteso. Missingembeddedimage: diagnosticoriginale, FAIL/noCAR/noIPA,
inputinvariati.60 lanci nativi osservati/zeroWSL; nipotiFoundation non journalati
individualmente, nessuna prova globaleprocess-tree/device/CoreUIcompleto. Tre
negative missingreference/unsupportedasset/invalidSVG conservate sul candidato0c,
non ribindate a6435. Restano namespace/risorse/tool parity, release/device e
validazioneprocess-tree; ambiguitàSVGexternalbases fallisce esplicitamente.

Stato corrente — SDK/compiler/macro/linker verificati — 2026-10-11.
CLI7c486843...eb0cb0f:59/59 PASS57.13s,34 diagnostici. OriginaleApple invariato
ancoraBSD366/capabilitypthread; no finti successi o Preview vuote. PercorsoPE
macro nativo automatico compilaObservable reale conSDK27/Swift6.4/LLVM23.1.3,
produceIPA unsigned verificata,32 processi senzaWSL. ProviderLLVM acquisito con
hash ufficiali/fallbackxz e validato sulloSDK originale. Prossimo gate referenceapp
pulita; il gruppoDarwin restaQoS/voucher/BSDcreation reale. GateM0–M8,
pluginMachOoriginali/app/release/zeroWSL globale incompleti; firma differita.
CURRENT_CHECKPOINT.md e proveindipendenti sono correnti; preludi seguenti storici.

Stato corrente M6 — peer Mach nativi e stato PAC — 2026-10-10.
CLI773765905a20872857cbae405c3ffd6070a874a96007df65f2e9ea095b6ebb28;
58/58 PASS52.41s, consumer integrazione ripetuto PASS8.58s,34 test diagnostici.
MIG3412 e3600/3605/3606: peer reali nello stesso motore, stato firmato originale
formato ARM64, sospensione contata, identità/TSD, dead-name e terminazione senza
ritorno; conversione AUTIA/AUTDA conserva poison e classifica fault reali.
Originale140.8077833s/146308380 callback: ancora BSD366/capability pthread;
95 hash/12 CMS/4715 pagine verificati, nessun peer/main/plugin originale provato.
Ledger45 scope/36 owned/4 originali; nessuna percentuale globale. Prossimo gruppo
QoS/queue/voucher e creazione BSD/registrazione reali. M0–M8/app/zeroWSL ancora
incompleti; firma differita. CURRENT_CHECKPOINT.md è corrente; preludi seguenti
storici, senza sostituire i gate e l'obiettivo completo del piano.

Stato corrente M6 — contesti CPU/TSD/PAC verificati —2026-10-09.
Core270e5b1/integratione364b39 nello stesso MachTask/Unicorn. Due contesti owned
mantengono registri/TSD/SIMD/FP/PAC separati e memoria condivisa; il motore originale
cattura solo il thread principale. Nessuno scheduler o capability fittizi.
53/53 PASS48.55s; CLI631a3540...14d525 installata, host/Unicorn/workspace uguali.
Originale113.606s: stesso BSD366/PC/input normalizzato del precedente checkpoint,
146308364 callback contro146308356 (+8, non prova di progresso/correttezza),
stop unsupported_pthread_capabilities.95 hash/12 CMS/4715 pagine verificati.
Ledger36 scope:21 entro scope,10 parziali,4 mancanti,1 unreviewed;27 owned/3 originali.
Il nuovo scope di cambio contesto è verificato owned, non sul percorso originale.
Prossimo gruppo: lifecycle/runnable/wait/termination, TSD/QoS e sincronizzazione
con i contesti reali. M0–M8/main/plugin/build/zeroWSL incompleti; firma differita.
CURRENT_CHECKPOINT.md corrente. Preludi seguenti storici.

Stato corrente M6 — registrazione pthread: copy-in verificato —2026-10-09.
Core f57e495; Release52/52 PASS50.13s. CLI684cadde...8ce951 installata,
host/Unicorn/workspace verificati. Originale112.875s: BSD366 PC0x18084ed30,
input16384/60 byte decodificato;56 noti/4 sconosciuti. Stop esplicito sulle
capability mancanti, nessuna registrazione/copyout/successo fittizio.95 hash,
12 CMS/4715 pagine e55 regioni VM indipendentemente verificati. Ledger35 scope:
20 implementati entro scope,10 parziali,4 mancanti,1 unreviewed;26 owned/3 originali
(nuovo scope originale: solo copy-in). Prossimo gruppo: contesti/TSD/QoS/scheduler
e sincronizzazione reali prima della pubblicazione capability. M0–M8/main/plugin/
build/zeroWSL incompleti; firma differita. CURRENT_CHECKPOINT.md è corrente.
Preludi seguenti storici.

Stato corrente M6 — gruppi Darwin e stop pthread reale —2026-10-09.
Ripresa chat_completa_pulita_2.md:32 dispatch fittizi rimossi; credenziali e query
code-sign source-backed, restartable ranges per singolo thread con stato/ABI veri.
Nessun salto PAC o bsdthread_register dummy. Candidato35da378d...37e2718 installato,
3 hash workspace/managed uguali.51 test superati (50 suite + fixture corretta1).
Originale113.493s/146308503 callback:BSD366 a0x18084ed30; main/plugin non avviati.
95 originali/12 CMS/4715 pagine/CDHash verificati; percorso originale ancora precedente
ai nuovi contratti. Ledger34 scope:19 implementati entro scope,9 parziali,5 mancanti,
1 unreviewed;25 prove owned/2 originali correnti. Report nativo per gruppi/backlog
riusa inventario/reachability/ledger;701 siti potenziali non sono701 funzionalità richieste.
Prossimo gruppo pthread/TLS:ABI registrazione/TSD, contesti, capability reali,
wait/wake/timeout/cancellazione insieme. M0–M8/build/plugin/zeroWSL incompleti,
firma differita. CURRENT_CHECKPOINT.md / DARWIN_RUNTIME_WORKGROUPS.md sono correnti.
Preludi seguenti storici.

Stato corrente M6 — VM anonima e replacement; clock timebase mancante —2026-10-09.
Core backing condiviso bf4a94e; guest NONE/max protection/partial unmap/overwrite/
MAP_FIXED preservano lease e byte,51/51 PASS. RuntimeCLIec1983da...5f5f17 installata;
originale116.57s/146340248 callback supera tag MIG4811 e vecchia assertion libmalloc.
95 hash originali,12 CMS/4715 pagine e contratti precedenti verificati. Prefisso32
regioni senza sovrapposizioni; full VM/overwrite originale diretto ancora da auditare.
Nuovo stop verificato Mach−89 timebase_info a0x180848ce8; prossimo ratio/copyout8 byte
coerente con clock Windows100ns, ABI XNU reale e stesso originale. Ledger30 scope:
14 implementati entro scope,9 parziali,5 mancanti,2 unreviewed;20 test/9 originali.
Diagnostica c1e8ccf corregge carrier64→ID signed, conserva raw e join statico Mach−89.
Producer4ea44670...32cec2 non è nuova prova runtime; candidato originale restaec1983da.
M0–M8/main/plugin/build/zeroWSL incompleti, firma differita, quality agente a fine
obiettivo completo. FonteCURRENT_CHECKPOINT.md / DARWIN_ANONYMOUS_VM.md.
Preludi seguenti storici.

Stato corrente M6 — 2026-10-09; preludi seguenti storici.
Misurazione nativa integrata: runtime report-progress, ledger per ambito, prove
legate a candidato/artifact/probe e confronto checkpoint; niente percentuali globali.
CLIf165f2f7...0498942 installata/uguale;50/50 PASS52.37s. Binari Apple invariati
superano ora lock ownership libplatform: kernel Mach names con bit bassi3.
Core4276aab;95 hash originali,12 CMS/4715 pagine verificati indipendentemente.
27 ambiti:11 implementati entro scope,9 parziali,5 mancanti,2 da revisionare;
17 ambiti verificati nei test,8 anche sul percorso originale.
Primo stop mach_vm_map/MIG4811: anonymous ANYWHERE+tag1,0x484000,current/maxNONE,
flags0x01000001 rifiutati dal guard~1 a0x180848c1c. Prossimo gate VM tag metadata,
current/max protection/reservation lifecycle e stesso consumer originale.
Calendario completo/pthread/Mach-MIG/TLS/ObjC/Swift/IPC/main/plugin/build e
zeroWSL ancora incompleti. Firma differita; quality agente a obiettivo completo.
Fonte corrente: CURRENT_CHECKPOINT.md e DARWIN_RUNTIME_PROGRESS.md.

Stato corrente M6 — 2026-10-09 (preludi precedenti storici).
Core registrazione firma source-backed b5f8b92; riusa CodeDirectory verifier e
CMS WinCrypt.48/48 PASS49.20s, consumer140 direct/indirect/errori/canary/READ
output e native descriptor/cursor/lease/mutazioni PASS. CLI6256f708...1141b817
installato/uguale. Originale4 F97 [0,87328,19040] successo/copyout90112;95 SHA,
22 pagine/slots e CMS indipendente positivo/negativo verificati.2,307,674 callback.
Nuovo errore confermato2 F_CHECK_LV98 [0,512,errptr] errno45, rawSVC0x18048a528;
prossimo gate policy libreria/task source-backed e ABI/errori/copyout. No fiducia
chain/platform inventata, BSD48 downstream non bypassato. Limiti native layout/
registrazioni espliciti; runtime mixed sperimentale. M0–M8/main/plugin/app/zeroWSL
incompleti, firma app differita, quality agente finale a obiettivo completo.
Nessun processo live. CURRENT_CHECKPOINT.md / DARWIN_FILE_SIGNATURE_REGISTRATION.md.

Stato corrente M6 — 2026-10-09 (preludi precedenti storici).
Candidate registrazione firma file/CMS nativo riusa verificatore CodeDirectory;
48/48 PASS48.36s, provider originale22 pagine/CMS PASS. CLIworkspace3c7daa8d...
6277fb2 non installato, core/guest ancora sperimentali/non committati. Originale
F97 richieste[0,87328,19040] success/copyout90112; nuova diagnostica libreria non
valida per il processo, probabilmente F_CHECK_LV98: localizzare ABI reale e
rafforzare test descriptor/lease/guest prima di promuovere. No fiducia chain/platform,
full95SHA verifier nuovo non ancora eseguito. BSD48 resta abort a valle.
Valutato ipsw esterno Windows3.1.732: firme Mach-O e cache originale80 membri/
4088 dylib PASS; APFS hidden/list-only, runtime non sostituito. Usarlo per inventario/
diagnosi, ingestion produzione solo dopo gate completi. IPSW_EXTERNAL_TOOL_EVALUATION.md.
M0–M8/main/plugin/app/zeroWSL incompleti; firma app differita, quality agente finale
solo a obiettivo completo. Nessun processo live. CURRENT_CHECKPOINT.md.

Stato corrente M6 — 2026-10-09 (preludi precedenti storici).
Policy task loader-path esplicita/core7ae2869; Release47/47 PASS52.32s,
consumer120 query/2 test PASS6.04s. CLIfe41b968...df8ae21 installato/uguale.
Originale AMFI90 input0/output1; rpath espanso, vero provider106368 byte aperto
2 volte e mappato, SHA b91e0982...29c74775.95 SHA e contratti precedenti/raw ABI
indipendentemente verificati; stderr40 write/1256 byte reali.2,318,187 callback.
Nuovo primo errore F_ADDFILESIGS_RETURN errno45; blob originale presente con
CodeDirectory/requirements/CMS, LC_CODE_SIGNATURE0x15520/0x4a60 verificato.
Prossimo gate ABI fcntl/registrazione source-backed e validazione reale, senza
fingere firma/platform trust. Firma app differita non elimina ABI loader.
Terminale BSD48 in abort a valle: non bypassare. Runtime mixed sperimentale;
main/plugin/app/zero WSL/M0–M8 incompleti, agente finale a obiettivo completo.
CURRENT_CHECKPOINT.md / DARWIN_LOADER_PATH_POLICY.md.

Stato corrente M6 — 2026-10-09 (preludi precedenti storici).
Output descriptor nativo/WriteFile reale e BSD4 ABI implementati, core5671874.
46/46 PASS46.62s, CLI72cd33a3...4f5321b6 installato/uguale workspace. Originale
16 write/467 byte stderr, confronto file/prefix/count/type e95 SHA indipendenti.
Messaggio dyld completo: at-path expansion vietata dalla policy. Provider originale
presente nel toolchain host, rpath @executable_path/../lib/swift/host immutato;
nessuna assenza da coprire con alias. AMFIcall90 attuale ENOPOLICY103 porta flags0.
Prossimo gate verificare ABI/raw consumer e policy esplicita task per path loader,
query generica senza fingere firma/platform trust; originale deve risolvere il
vero provider. Stop terminale BSD48 in fatal, non bypassarlo prima della causa.
Callbacks2,034,844; main/plugin/app/zero WSL/M0–M8 incompleti, firma differita,
agente finale solo a obiettivo completo. CURRENT_CHECKPOINT.md/DARWIN_NATIVE_OUTPUT.md.

Stato corrente M6 — 2026-10-09 (preludi precedenti storici).
Mmap privato da lease/source originali implementato; core00a3d76,45/45 PASS47.72s,
CLI e0b8430a...0401652e installato/uguale workspace. Originale BSD197 errno0,
71680 byte source/81920 mapped; chiude fd e continua1,728,895 callback.95 SHA,
metadati/source/size e SVC verificati. Consumer COW/cursor/closed-fd/partial munmap,
WRITE_PROT e pagina rimossa READ_UNMAPPED;120 query errori.0x40002=PRIVATE|UNIX03.
Nuovo stop BSD4 write stderr2, richiesti9 byte prefisso "dyld[2]: "; causa del
messaggio dyld completo ancora non localizzata. Provider Swift reale presente
nel toolchain host, assente solo fallback /usr/lib/swift: non inventare alias o
concludere assenza. Prossimo gate trasporto stderr nativo/copyin/counts, acquisire
intera diagnostica originale e riparare primo contratto causale. Mapping EOF
pager/shared/fixed/JIT/anon, credential/VM/IPC generali restano incompleti;
M0–M8/main/plugin/app/zero WSL incompleti, firma differita, agente finale solo
ad obiettivo completo. CURRENT_CHECKPOINT.md e DARWIN_PRIVATE_FILE_MAPPING.md.

Stato corrente M6 — 2026-10-09 (preludi precedenti storici).
Metadati regular-file Stat/Fstat da lease Windows, layout Darwin144, owner/group
SID nativi e ACL projection read-only; core eb6af79.44/44 PASS48.25s, consumer
160 query e install identity verificati: CLI2226a9be...92387c9e. Originale stat64
errno0/copyout reale,95 SHA e metadati Windows indipendenti; LDR originale legge
71680 aoutput+96.1,331,522 callback, nuovo stop BSD197 mmap0x18048b43c:
[0,71680,1,0x40002,3,0], actual server lease fd3. Prossimo gate mapping privato
source-backed/offset/EOF/protection/lifetime, stesso originale; nessun trust firma
fittizio. Credential/token equivalenza e directory metadata restano incompleti.
M0–M8/main/plugin/app/zero WSL incompleti; firma differita e agente finale solo
ad obiettivo completo. CURRENT_CHECKPOINT.md e DARWIN_FILE_METADATA.md.

Stato corrente M6 — 2026-10-09 (preludi precedenti storici).
CS_OPS_STATUS implementa lo stato esplicito del task nativo, senza firma validata
ne' enforcement/provider/platform trust. ABI XNU usersize ignorato/output null,
PID/copyout/errori/flag verificati:43/43 PASS45.64s e consumer rafforzato160 query
PASS6.05s sullo stesso CLI dda746d2...7233a4f installato/uguale al workspace.
Originale self/status errno0/copyout0; consumer bit26/raw SVC e95 SHA invariati
verificati;1,331,398 callback. Nuovo stop BSD338 stat64 sul vero server Apple.
Prossimo gate metadati generici source-backed/layout Darwin/identity e ownership;
nessun inode/UID Apple inventato. M0–M8/process/plugin/app/zero WSL incompleti;
firma packaging differita, agente finale solo a obiettivo completo. Stato/prove:
CURRENT_CHECKPOINT.md e DARWIN_CODE_SIGN_STATUS.md. Runtime ampio sperimentale.

Stato corrente M6 — 2026-10-09 (preludi precedenti storici).
Commpage debugger gestita da policy nativa esplicita senza provider kernel-debug;
43/43 PASS45.40s, CLI installato5160607e...3f06e872. Originale legge uint32 0
RO+0x84, procede1,184 callback a1,294,106;95 SHA e read/path/SVC verificati.
Nuovo fatal originale: failed to open root directory: /: 45; flags0x20100000
O_DIRECTORY | O_NOFOLLOW_ANY. Prossimo gate: catalogo directory originali,
descrittori owned e semantica no-symlink/canonical path, stesso originale.
Corretto nome vecchio flag /dev/null0x20000: O_NOCTTY (O_NOFOLLOW e'0x100).
M0–M8/processo/plugin/app/zero WSL ancora incompleti; firma differita. Agente
finale solo a obiettivo completo. CURRENT_CHECKPOINT.md contiene prove/limiti.

Stato corrente M6 — 2026-10-09 (preludi precedenti storici).
Corretto PID1 assegnato erroneamente a processo ordinario: namespace riserva0/1,
primo PID2, test cold/concorrenza e43/43 PASS46.27s. CLI installato0cbfa5ef...2849650a.
Originali: getpid2/Sandbox2 verificati; fatal riserva stdin scompare,1,292,922
callback (+5,292);95 SHA e branch/LDR raw verificati. Nuovo stop commpage RO+0x84
(uint32 debugger capability), PC0x1805023b0/address0xfffff4084. Prossimo gate:
stato debugger nativo esplicito, alias/ABI/bounds/readback e stesso originale.
/dev/null/standard I/O ancora incompleti; nessun processo/plugin/app/zero WSL
completato, M0–M8 e firma differita invariati. CURRENT_CHECKPOINT.md e
DARWIN_PROCESS_IDENTITY.md riportano prove/limiti. Agente finale a obiettivo completo.

Stato corrente M6 — 2026-10-09 (preludi precedenti storici).
Sysctl MIB/name2oid generico e assenza MAC ENOPOLICY superati sul binario originale;
42/42 PASS46.66s, CLI installato0406c99f...60774bee,95 SHA verificati.
Osservazione bounded del messaggio originale, senza modificare esecuzione:
failed to reserve stdin descriptor: /dev/null: 45; stop1287630/BSD48 in abort.
Raw originale: getpid==1 entra in riserva stdin/stdout/stderr; allocatore nativo
assegna impropriamente PID1 a processo ordinario. Prossimo gate: riservare0/1
(kernel/init), test cold/concorrenza e propagazione getpid/Sandbox, stesso probe.
/dev/null/standard I/O ancora incompleti: non dichiararli risolti con PID normale.
Nessun plugin/processo/app/zero WSL completato; M0–M8 e firma differita invariati.
Evidenza riproducibile: CURRENT_CHECKPOINT.md. Nessun agente finale prima del
completamento dell'intero obiettivo.

Stato corrente M6 — 2026-10-09 (preludi precedenti storici).
Query originale Sandbox syscall-unix/550 superata da stato esplicito task senza
profilo; PID owned/getpid coerenti, ABI/copyout/permessi verificati.41/41 PASS
44.99s, CLI installato24644914...ff51ccdf. Stesso originale1,277,689 callback:
+403, nuovo stop BSD202 __sysctl, nome security.mac.lockdown_mode_state; caller
name2oid con costante originale[0,3].95 SHA e SVC/stringhe raw verificati.
Prossimo gate: copyin MIB vivo e registro sysctl generico da stato nativo reale,
assenza nodi opzionali ENOENT senza inventare policy/versioni. Nessuna disponibilita'
fittizia di syscall550; processo/plugin/app/zero WSL/M0–M8 incompleti. Firma
differita, agente finale solo a completamento obiettivo. Runtime ampio ancora
sperimentale/non committato. CURRENT_CHECKPOINT.md e DARWIN_SANDBOX_CHECK.md.

Stato corrente M6 — 2026-10-09 (aggiornamenti precedenti storici).
Primitive file originali read-only implementate con catalogo derivato dal loader,
handle Windows stabili/SHA/namespace descriptor per-task: open/close/read/pread/
seek/flags e F_GETPATH.41/41 test PASS48.19s, CLI installato7bfd4fb7...19e53de3.
Originale open/F_GETPATH/close PASS sul server Apple;95 SHA e4 SVC verificati.
Bootstrap1,277,286 callback: primo stop ora MAC Sandbox call2/BSD381. Processo,
plugin/output/app/IPA/zero WSL ancora incompleti; firma differita. Primitive e
catalogo in commit separato; guest hooks e runtime Antigravity ancora sperimentali.
Prossimo gate: policy/ABI Sandbox effettivi senza risposta allow incondizionata,
poi stat/mmap e altri servizi realmente richiesti. CURRENT_CHECKPOINT.md e
DARWIN_ORIGINAL_FILES.md contengono identita', evidenze e limiti riproducibili.

Stato corrente — 2026-10-09 (aggiornamenti precedenti sotto sono storici).
Ripresa della chat Antigravity: APFS type7/8 e dyld originale estratto confermati;
corretto controllo LZVN EOS/output parziale, mantenendo i tail validi dei blocchi.
Corrette le protezioni VM NONE e il backing host per reprotection; aggiunti
controlli bounded ai messaggi MIG e test negativi. Build/test/install41/41 PASS.
CLI c1f0cd6e...430e170b; original probe523 immagini/1,269,233 callback, stop BSD
open5 sul vero swift-plugin-server.95 SHA256 originali e SVC grezzo verificati.
Processo/plugin/output/app/IPA/zero WSL incompleti. Modifiche runtime Antigravity
ancora sperimentali/non committate; non sono accettate in blocco come corrette.
Prossimo gate M6: completare revisione VM/MIG e filesystem Darwin dei file
originali (open/read/stat/mmap), poi stesso bootstrap. Firma saltata come richiesto.
Dettagli riproducibili e limiti: docs/CURRENT_CHECKPOINT.md.

M6 APFS ordinary originale —2026-10-08: parser FS virtuale/checksummato e
extent in-tree implementato;41/41 PASS43.20s, candidato21f8cb45...cff632.
Input OS originale stesso SHA preservato; inventory PASS45,908 nodi/1,746,020
record/514,409 percorsi. Verifica indipendente512 OMAP+45,908 FS checksum/XID,
footer/conteggi PASS. /usr/lib/dyld presente regolare compresso; non ancora
estratto/eseguito. Seal=false e data=false per ordinary; sealed invariato.
Raw decmpfs type8/decoded4,129,840/resource1,555,501/default_crypto_id0:
aggiungere decoder generico type8 (attualmente13/14).
Prossimo contratto estrazione compressed source-bound, poi interprete originale
LC_LOAD_DYLINKER e producer/restart cache reali. APFS_ORDINARY_BOOTSTRAP_INPUT.md.
M0–M8/process/plugin/app/zero WSL restano incompleti; nessun handle live.

M6 input originale bootstrap OS —2026-10-08: header cached entry uguale al PC;
nessun entry alternativo inventato. Nuovo componente OS stessa build27.0.1/
26A434 acquisito/decodificato CLI nativo,11274289152 encrypted/14189330432
decoded;53 cluster/13532 segmenti autenticati; digest SHA384 manifesto coincide,
CRC e hash indipendenti PASS. SDK/cache precedenti invariati e preservati.
OS metadata APFS PASS checkpoint683; tree FAIL variante non sealed (incompat1,
root_type2, integrity/fext_oid0). Implementare parser ordinary FS/extent con
checksums/OMAP/versione e seal separato; poi leggere interprete disk originale
e risolvere bootstrap/cache transition. Nessuna ripetizione download/decode.
DYLD_CACHE_TRANSITION_DIAGNOSIS.md / CURRENT_CHECKPOINT.md; processo/plugin/
app/M0–M8/zero WSL ancora incompleti. Nessun handle live.

M6 transizione cached-dyld localizzata —2026-10-08: nuovo trace nativo64
registri/load mapped verificati;41/41 PASS45.16s, originale6322 callbacks
invariati/523 immagini/30487909 fixup/94 hash. Simbolo originale
completeAllImageInfoTransition; global punta all'export _dyld_all_image_infos,
campi trasferimento+0x48/+0x138 zero: manca producer disk-dyld prima del restart.
Non sintetizzare stato o saltare il consumer. Usare interprete originale su
disco da LC_LOAD_DYLINKER, selezione per ruolo/risoluzione tree-cache, quindi
preparazione/restart originali. DYLD_CACHE_TRANSITION_DIAGNOSIS.md.
Process/plugin/app/zero WSL e M0–M8 restano incompleti.

M6 diritti Mach nativi —2026-10-08: backup ricontrollato invariato;
mod_refs/deallocate da namespace owned, receive/dead-name/lifetime/pegged refs,
riacquisizione thread e ABI preservata. Pinned last ref stop esplicito;
guard/IPC/notifiche restano aperti.41/41 PASS44.47s, originale exit1/72.331s:
523 immagini/30487909 fixup/445 target/522 ordine/94 hash invariati.
4464->6322 callback; -19 refs2->1 consumato, -18 solo test owned.
Nuovo stop READ8 a0x20, PC0x1804d8f3c/raw0xf9401129, X9=0.
Localizzare producer/consumer del puntatore nullo senza iniezione/stub.
DARWIN_NATIVE_MACH_RIGHTS.md / CURRENT_CHECKPOINT.md. M0–M8, process/plugin/
output, app e zero WSL incompleti; firma saltata come richiesto.

M6 stato dinamico cache posseduto —2026-10-08: riserva da header originale,
v3/identità reale file Windows/percorso virtuale/default variant bit0, regione
anonima separata/READ/lifetime; nessun byte sintetico nel reader degli originali.
41/41 PASS43.37s; originale exit1/68.339s,523 immagini/30487909 fixup/445 target/
522 ordine/94 hash invariati.4407->4464 callback, consumer magic superato.
Nuovo SVC0x1804875e4/raw0xd4001001, trap Mach-19 mod_refs/task260/name260/SEND/
delta-1. Implementare gruppo diritti/ref/deallocate/lifetime coerente, senza
stub permissivi backup. DYLD_NATIVE_DYNAMIC_DATA.md / CURRENT_CHECKPOINT.md.
M6/process/plugin/output/M0–M8/zero WSL restano aperti.

M6 TPRO cache preflight —2026-10-08: mapping flags conservati, permessi runtime
RW solo per CONST_TPRO_DATA bit6; originali initial/max distinti, altri mapping
protetti.41/41 PASS43.72s; originale exit1/70.916s,523 immagini/30487909 fixup/
445 initializer/522 ordine/94 hash invariati.1346->4407 callback: scrittura
precedente superata; query shared-region originale consumata1. Nuovo stop
READ_UNMAPPED8 byte0x339b10000, PC0x180492a5c/raw0xf9400149. Header originale
conferma dynamicDataOffset/base e max16384: implementare produttore di stato
runtime e lifetime, senza zeri sintetici nei file. DYLD_NATIVE_TPRO_MAPPING.md.
Avvio cache/IPC/plugin/output/M0–M8/zero WSL ancora aperti.

M6 adozione selettiva Antigravity —2026-10-08: backup e allegato ricontrollati;
ID guest allocati, ABI BSD X0/X1/carry/NZV, TSD TPIDRRO, crossarch uint32,
dyld flags e CSR copyin/out con permessi. Query shared-region da mapping reale,
unmap non simulato. Port refs difettosi, massimo WRITE automatico e dynamic data
sintetica non importati.41/41 PASS42.19s; originale exit1/64.314s,523 immagini/
30487909 fixup/445 target/522 ordine/94 hash invariati;183->1346 callback.
Nuovo stop WRITE_PROT:4 byte0x1e60e00f7, PC0x1804f79b0/raw0xb801f01f,
.25.dylddata initialREAD1/maxRW3. Localizzare transizione/owner VM; non bypassare
protezioni. Query originale calls0; process/plugin/output ancora incompleti.
Inventario aggiornato11 handler/CLI hash/provenienza,14 LLVM+523 raw PASS.
ANTIGRAVITY_ADOPTION.md / CURRENT_CHECKPOINT.md. M0–M8 e zero WSL restano aperti.

M6 riferimento AnyPS5 verificato —2026-10-08: analizzati12 file al commit
 df16c4c256be3c44e03eb9149a6ce5f8e8a038b2, con hash/provenienza esterni. Adottare
la suddivisione per servizi con ownership condivisa, registro import/call-site
con confidenza, controllo ABI/TLS e memoria/descriptor tracciati. Il progetto
converte ELF x86-64 in PE e fornisce librerie native sostitutive; lo scanner
standard rifiuta syscall dirette. Non equivale al backend Mach-O/ARM64 originale
richiesto. Restano originali Apple e Unicorn, con provider Darwin al confine OS.
Le184935 importazioni non sono184935 API da riscrivere: molti simboli hanno
codice Apple originale; occorre chiudere contratti kernel/runtime sottostanti.
Nessuna potatura import non provata, modifica upstream, conversione PE o stub
successo introdotta. Dettagli e fonti: ANYPS5_ARCHITECTURE_REFERENCE.md.
Prossimo errore verificato sempre thread_selfid372/ABI BSD; goal ancora aperto.

M6 relocated commpage geometry —2026-10-07: native RO page and legacy aliases
publish kernel/user64 page shifts calculated from actual owned stack page
policy; complete one-byte fields only, readbacks/range/write/fetch rejection,
RAII rollback/teardown.41/41 PASS41.59s; original exit1/65.785s,523 images/
30487909 fixups/445 targets/522 order and94 hashes unchanged. Original dyld
reads1 kernel/1 user, value14 agrees with owned16384-byte guest VM policy and
raw byte-load instructions.148->183 callbacks; next SVC0x80 at0x18048ad40,
selector372: BSD thread_selfid, uint64_t current thread identity. BSD ABI/service
unavailable; no fake return or process completion. Next coherent context/TLS
and BSD return ABI. DARWIN_NATIVE_COMMPAGE_GEOMETRY.md / CURRENT_CHECKPOINT.md.

M6 reply/current-thread port context —2026-10-07: native namespace allocates
ordinary receive-only reply ports, coalesces current raw-thread send rights,
and allocates/rebinds special send+receive replies. Owned task/engine/context,
rights/lifetime and invalid-name/SVC checks; native constexpr dispatch registry.
41/41 PASS41.23s; original exit1/64.897s,523/30487909/445/522 and94 original
hashes unchanged. Reply port516/typeRECEIVE/refs0 independently verified at
raw SVC0x180487638; original thread/special calls0 (owned tests only).
139->148 callbacks; next read1 byte0xfffff4037 atPC0x18048ac54/raw0x39404929,
relocated read-only commpage kernel page shift. No field supplied or process
success asserted. Static availability now consumes actual six-handler native
registry +candidate hash, rather than a separate hardcoded handler list.
DARWIN_NATIVE_PORT_CONTEXT.md / CURRENT_CHECKPOINT.md. IPC/VM/runtime remain open.

M6 task/port ownership and static inventory —2026-10-07: native task_self_trap
implemented against actual guest task/engine/namespace, rights and lifetime.
41/41 PASS43.65s; original exit1/70.342s,523 images/30487909 fixups/445 targets/
522 order/94 original hashes unchanged. Actual port260/typeSEND/refs2 resolves
actual guest;139 callbacks, next original SVC at0x180487638 selector-26
(mach_reply_port), still explicit unsupported. Complete process/plugin open.
User steers next work to static inventory then coherent service groups:
620 XNU domain/ID entries (conditional definitions preserved),709 raw SVC sites,
698 local selector candidates,311931 imports/184935 unique symbols,487489 exports.
All14 standalone UNDEF sets compared with LLVM;523 raw export counts agree;
45 accessed original source files fully rehashed.11 selectors unresolved and
optimized cache/dynamic lookup coverage incomplete. Counts are not runtime
frequency or proof of reachable calls. Implement ports/thread context, guest VM,
IPC, filesystem and synchronization in coherent batches with original-path
verification; unknown services stop explicitly. DARWIN_STATIC_INVENTORY.md.

M6 kernel-debug capability: KDEBUG_ENABLE0xfffffc100/4 byte dichiara0 dalla
configurazione nativa priva di collector/typefilter Darwin. Letture fuori campo,
write/fetch e servizi non implementati restano errori.41/41 PASS43.31s;
originale exit1/66.010s,523 immagini/30487909 fixup/445 target/522 ordine e94 hash
invariati. Campo consumato1 volta,98->133 callback; prefix16/ultima istruzione
concordano raw. Nuovo stop SVC0x80/PC0x180487650/selector-28: task_self_trap.
Prossimo contratto task/port namespace nativo con diritti/lifetime reali, nessun
port costante fittizio. Processo/plugin/output ancora incompleti.
Vedere DARWIN_NATIVE_KDEBUG_CAPABILITY.md / CURRENT_CHECKPOINT.md.

M6 clock fallback nativo: CONT_TIMEBASE da snapshot stabili Windows, trap
absolute/continuous precise100ns, ABI SVC/PC/X16 verificata. Unknown campi e
interrupt restano errori.41/41 PASS46.89s; originale exit1/71.200s,523 immagini/
30487909 fixup/445 target/522 ordine/94 hash invariati. Da35 a98 callback;
CONT_TIMEBASE letto2 volte e trap absolute originale1, PC0x1804885d0/raw SVC
concorde, valore entro intervallo clock host e bias0 verificato indipendentemente.
Nuovo stop KDEBUG_ENABLE0xfffffc100/4 byte, PC0x1804879f8/opcode0xb9400108.
Conversion service e suspend hardware test non eseguiti; processo/plugin/output
ancora incompleti. Vedere DARWIN_NATIVE_COMMPAGE_CLOCKS.md / checkpoint.

M6 commpage clock capabilities: pagina guest read-only0xfffffc000, solo
USER_TIMEBASE0x090=NONE / CONT_HWCLOCK0x091=false dichiarati. Letture sconosciute
incluse larghezze che attraversano i campi rifiutate; write/fetch protetti.
41/41 PASS45.11s. Originale exit1/71.454s:523 immagini/30487909 fixup/445 target/
522 ordine e94 hash originali invariati; lettura precedente superata,35 callback.
Nuovo stop: CONT_TIMEBASE0xfffffc098,8 byte, PC0x180506598 opcode0xf9400268;
prefix16/ultima istruzione concordano raw. Prossimo: clock/timebase coerenti
Windows/Darwin e trap originali; processo/plugin/output ancora incompleti.
Vedere DARWIN_NATIVE_COMMPAGE_CAPABILITIES.md e CURRENT_CHECKPOINT.md.

M6 bootstrap reale: probe-cache-arm64 avvia il PC originale dopo preparazione
verificata e si ferma al primo interrupt/accesso memoria/errore, con budget100000
callback/2s e cancellazione. Fixture Clang/LLD SVC/read unmapped/loop verificati;
41/41 PASS48.21s. Originale exit1/75.091s: mapping523 immagini/30487909 fixup,
445 target/522 ordine e94 SHA invariati;30 callback osservate, prefix16 e ultima
istruzione concordano raw. Prima lettura mancante:0xfffffc091, PC0x180506568,
opcode0x385f9268,1 byte. XNU identifica _COMM_PAGE_CONT_HWCLOCK (commpage+0x091).
Processo/plugin/output non completati; prossimo contratto commpage/clock nativo,
nessun successo fittizio da pagina zero. Vedere DARWIN_NATIVE_BOOTSTRAP_PROBE.md.

M6 initial ARM64 thread: mapper segue interpreter edge originale, verifica
identita stack/immagini e ricava PC runtime/SP KernelArgs; guest applica/legge
31 GPR, PC, SP e PSTATE. Stato privilegiato/flag opaque e custom SP rifiutati.
Fixture ARM64 own preserva X0/X28/NZCV non nulli e resetta altri GPR/FP/LR;
41/41 PASS43.03s. Originali prepare-cache-arm64 exit0/64.168s:523 immagini/
30487909 fixup/445 target/522 ordine,94 SHA invariati. Registri effettivi e stato
originale raw concordano; nessuna istruzione Apple ancora eseguita. Prossimo:
bootstrap dyld originale limitato, osservare prima dipendenza Darwin mancante.
Vedere DARWIN_NATIVE_INITIAL_THREAD.md e CURRENT_CHECKPOINT.md.

M6 Unix thread metadata: parser condiviso standalone/cache conserva tutte le
parole originali LC_UNIXTHREAD, PC/SP x86_64/ARM64; geometria/flavor/count,
owner/entry eseguibile e duplicati/conflitti validati. Fixture proprie dichiarano
il formato in header padding richiesto al linker; primo test senza spazio falliva.
41/41 PASS43.29s. CLI inspect-cache-closure e verifica raw originale PASS24.878s:
523 immagini, un solo comando nel dyld originale, PC coerente con cache entry e
94 SHA invariati. Nessun registro Apple ancora applicato/eseguito. Prossimo:
stato iniziale CPU da interpreter e stack, servizi Darwin e avvio originali.
Vedere DARWIN_NATIVE_UNIX_THREAD.md e CURRENT_CHECKPOINT.md.

M6 startup Apple parameters: ProcessStack genera main_stack dalla riserva
Windows effettiva e stack_guard/malloc_entropy/ptr_munge tramite CNG; byte zero
del guard, cardinalita, conflitti caller e entropia per processo verificati.
41/41 PASS43.89s. Originali prepare-cache-arm64 exit0/68.761s:523 immagini/
30487909 fixup/445 target/522 ordine,94 SHA invariati. Tutte le cinque stringhe
Apple e puntatori letti dal guest concordano; nessun valore entropia nei log.
Avvio processo/servizi/runtime/IPC e zero WSL restano aperti.
Vedere DARWIN_NATIVE_STARTUP_PARAMETERS.md e CURRENT_CHECKPOINT.md.

Backend CPU 2026-10-07: l’utente autorizza esplicitamente Unicorn su Windows.
Il requisito zero WSL e l’integrita di binari/sorgenti Apple restano invariati.
La slice ARM64 originale e quindi un input consentito per il percorso principale;
assenza di x86_64 non blocca questo percorso, ma il runtime deve eseguire gli
originali e produrre output consumato prima di dichiarare M6 completato.

M6 guarded stack: riserva Windows, memoria RW e guardie non committate,
frame KernelArgs/ProgramVars rilocato, dimensione da LC_MAIN/limite/default
macOS per CPU. Consumer Darwin sulla CPU Windows e lifetime PASS;41/41 PASS41.45s.
Originali prepare-cache-arm64:exit0/64.880s,523 immagini/30487909 fixup/445 target/
522 ordine,94 SHA invariati; SP e guardie verificati nel backend Windows.
Nessun processo Apple eseguito. Vedere DARWIN_NATIVE_GUARDED_STACK.md.

Riallineamento stessa ISA 2026-10-07: nuova inspect-image nativa sui14 file
originali trattenuti del grafo server/plugin conferma14 slice ARM64, zero x86_64;
host del processo x86_64 e tutti gli hash invariati. Nessun download/patch.
La priorita resta loader e runtime Darwin Windows con esecuzione diretta della
stessa ISA; il backend Unicorn ARM64 non prova quel gate. Per questo archivio
una slice x86_64 non puo essere selezionata: occorre una distribuzione originale
compatibile, oppure una build upstream invariata con metadata/toolchain validi;
nessuna alternativa e ancora verificata. Vedere DARWIN_SLICE_INVENTORY.md.

M6 process arguments: blocco Windows nativo KernelArgs/argv/envp/apple e
ProgramVars derivati da eseguibile originale e input caller; budget/NUL/lifetime
validati. Consumer C Darwin eseguito su CPU Windows con ABI SysV:42;41/41
PASS45.16s. CLI prepare-cache-arm64 registra lo stesso backing nel guest e
legge header/argc. Originali:exit0/73.325s,523 immagini/30487909 fixup,445 target,
522 order entries/94 SHA; entry displacement3080 e hint0 originali verificati.
Errore diagnostico campo segments corretto leggendo header originale, senza
rerun mapper. Blocco argomenti non e stack/processo avviato: TLS/ObjC/servizi/
IPC/output, stessa ISA e zero WSL restano aperti. Vedere DARWIN_NATIVE_PROCESS_ARGUMENTS.md.

M6 eager initialization order: grafo originale in ordine dipendenze, cicli una
sola volta, upward differite e root plugin condivise; interpreter escluso dalla
sequenza dylib. Fixture own normal-cycle/two-upward-levels: costruttori eseguiti
sulla CPU Windows producono123456; CLI/mapper propagation PASS;41/41 PASS42.38s.
LLD ignora upward_library: due soli tipi comando modificati nelle fixture own.
Originali:523 immagini/30487909 fixup/445 target;522 immagini ordinate concordano
con dipendenze raw110 upward e riferimento Apple pinned;94 SHA invariati,
exit0/67.007s. Nessun processo/costruttore Apple eseguito; policy delayed/ObjC/
TLS/servizi/IPC/output, stessa ISA e zero WSL restano aperti.
Vedere DARWIN_NATIVE_EAGER_ORDER.md e CURRENT_CHECKPOINT.md.

M6 initializer decoding: target dei costruttori ricavati dalla memoria privata
dopo tutti i fixup; pointer e offset, budget/geometry/read-only/executable checks.
Fixture costruttori Clang/LLD eseguite direttamente sulla CPU Windows:0->42,
discovery non esegue codice; pointer rebase reale e CLI PASS;41/41 PASS47.55s.
Server+PreviewsMacros originali via CLI installata:523 immagini/30487909 fixup,
445 target da20 sezioni concordano con raw Apple,94 SHA invariati;exit0/70.972s.
Nessun costruttore Apple eseguito. Ordine dipendenze/ObjC/TLS/processo/IPC/output,
esecuzione stessa ISA e zero WSL restano aperti. Vedere DARWIN_NATIVE_INITIALIZERS.md.

M6 startup metadata: parser sezioni originali e LC_MAIN collegati a immagini,
cache e closure native Windows. Fixture Clang/LLD costruttori pointer/offset,
TLS/unwind e rejection PASS;41/41 PASS43.25s. CLI installata sul grafo originale:
523 immagini/14624 sezioni, tutti i campi e LC_MAIN concordano con lettura raw;
94 file SHA invariati. Geometria/allineamento cache distinti da standalone sulla
base dei byte originali. Avvio processo, servizi Darwin, esecuzione stessa ISA,
IPC/output macro e rimozione WSL restano aperti.
Vedere DARWIN_NATIVE_STARTUP_METADATA.md e CURRENT_CHECKPOINT.md.

M6 weak lookup: flag Mach-O originali, ordinal-3, ricerca shallow/reexport e
selezione canonica weak/strong nel gruppo globale iniziale implementati. Fixture
Clang/LLD weak11/22, ordine invertito e strong33 PASS;41/41 PASS42.40s. Server+
PreviewsMacros originali via CLI installata PASS:523 immagini/157 range/30487909
fixup,66.053s; entrambi i target weak concordano con export originali,94 sorgenti
SHA invariati e conteggi grezzi indipendenti. Processo/init/IPC/output macro,
cache weak overrides/dynamic scopes/flat lookup e zero WSL restano aperti.
Vedere DARWIN_NATIVE_WEAK_LOOKUP.md e CURRENT_CHECKPOINT.md.

M6 plugin roots: vettore di immagini originali propagato al mapper/Guest e
alla CLI map-cache-arm64; fixture Clang/LLD aggiuntiva con bind/rebase PASS,
root assente rifiutata;41/41 PASS41.34s. Server+PreviewsMacros originale exit1
al namespace flat/weak: due import ordinal-3 (new/delete), definizioni weak
presenti nella cache originale,94 sorgenti SHA invariati. Prossimo contratto:
resolver weak/coalescing generico, senza special case di nomi/provider.
Mapping/plugin execution/processo/output consumer/zero WSL restano aperti.
Vedere DARWIN_NATIVE_PLUGIN_MAPPING.md e CURRENT_CHECKPOINT.md.

M6 loader: mapper Windows integrato con memoria privata cache originale,
indirizzi guest originali, fixup versione5 e firma PAC nello stesso engine.
Server Apple originale via CLI installata PASS:66 immagini/153 range/30485235
fixup,59.09s;93 file sorgente SHA invariati e conteggi verificati indipendentemente.
Crash iniziale nella traduzione CPU riprodotto con probe proprio; flush periodico
passa12 milioni di firme e il mapper originale. Fixture cache propria autentica
il puntatore ed esegue codice guest restituendo42. Il mapper sopra e server-only:
plugin roots, inizializzazione/processo/IPC, output macro consumato e zero WSL
restano aperti. Vedere DYLD_NATIVE_CACHE_GUEST.md e CURRENT_CHECKPOINT.md.

M6 backend ARM64: EL0 selezionato e verificato nel percorso C++/CLI; PAC IA/DA e
rifiuto istruzioni privilegiate PASS. Eccezione precedente localizzata nel probe:
azzerava SCTLR.nTWI e il backend fermava l'esecuzione tramite WFI. Nessun limite
EL0 o patch Apple necessari. CLI installata su Mach-O proprio: NOP42/CurrentEL
rifiutato. Build/install41/41 PASS40.56s. Firma/fixup cache nello stesso engine e
processo Apple restano aperti. Vedere DARWIN_ARM64_EL0.md e checkpoint.

M6 backend ARM64: inizializzazione Windows delle chiavi PAC casuali e controlli
CPU non-secure nel percorso di esecuzione nativo. Mach-O propri compilati/CLI:
firma IA/DA, autenticazione e rifiuto PAC alterato PASS; stesso input invariato
baseline6/candidato7. Build/install41/41 PASS40.15s. Processo Apple non validato:
EL0 genera eccezione anche su NOP nell'esperimento separato; fixup cache ancora
non applicati. Vedere DARWIN_ARM64_POINTER_AUTHENTICATION.md e checkpoint.

M6 loader: decoder Windows nativo delle catene slide versione5 originali PASS;
14 intervalli/26524 pagine/30452720 record; tutti i campi e hash canonico concordano
indipendentemente.11531881 puntatori autenticati/86052 tag preservati come metadata.
Build/install41/41 PASS40.50s. Non applicati fixup e non validata autenticazione:
integrazione mapper/backend/PAC/binding/processo Apple ancora aperti. Vedere
DYLD_NATIVE_CACHE_SLIDE.md. Nessun file Apple o sorgente upstream modificato.

M6 loader: memoria privata file-backed Windows sui80 file cache originali PASS;
101 intervalli/7029178368 byte,202 campioni e geometria raw concordano indipenden-
temente,17 offset non allineati gestiti. Scritture private/hash originali invariati,
lifetime lease e CLI verificati nei test. Build/install41/41 PASS41.49s. Viste host
associate agli indirizzi guest; integrazione backend/fixup/binding/processo Apple
ancora aperti. Nessun file Apple modificato. Vedere DYLD_NATIVE_CACHE_MEMORY.md.

M6 loader: DarwinClosure integrato con vista cache originale e lease mantenuti;
CLI finale sul server/plugin invariati:523 immagini (14 tree+509 cache),5694 archi,
tutti i path forti risolti/5 deboli assenti. Confronto indipendente metadati/path e
conteggi448357 export cache PASS. Mapper ARM64 originale supera il gate provider
mancanti e si ferma alle mappature VM/fixup cache non implementati. Build/install
41/41 PASS41.25s. Prossimo contratto: mappature globali guest cache/fixup/binding;
processo Apple, macro consumer e zero WSL aperti. Vedere DYLD_NATIVE_CACHE_CLOSURE.md.

M6 loader dyld: lettore export originale Windows nativo collegato alla vista VM;
indirizzi derivati dal LINKEDIT originale, stesso parser trie delle immagini normali.
CLI finale sulle sei identita forti mancanti del server/plugin:33777 record export
verificati indipendentemente,686 reexport/5 assoluti. Placeholder vuoti validi,
nessun repack/metadata Apple alterato. Build/install41/41 PASS42.15s. Restano
integrazione provider/resolver/mapper, chiusura reexport/dipendenze, fixup/runtime/
processo Apple e zero WSL. Vedere DYLD_NATIVE_CACHE_EXPORTS.md e checkpoint.

M6 loader dyld: lettore VM nativo con lease Windows mantenuti per tutti i file
originali, SHA/layout derivati e letture tra backing file adiacenti. CLI installata
legge4088 immagini originali+dyld:159416 comandi,25470 segmenti,89401 dipendenze;
confronto indipendente di UUID/campi/hash header-table PASS. Nessun repack/offset
Apple alterato. Build/install41/41 test PASS39.79s. Restano export/LINKEDIT, collega-
mento al resolver/mapper, fixup/ABI/processo Apple e zero WSL.
Vedere DYLD_NATIVE_VM_IMAGES.md e CURRENT_CHECKPOINT.md.

M6 loader dyld: tutte79 subcache Apple originali e principale estratti/verificati
nativamente (7043809280 byte,429920 hash APFS). CLI inspect-dyld-cache-set deriva
101 mappature combinate senza sovrapposizioni; copertura4088 header e4088 range
testuali. Confronto indipendente di tutte le mappature PASS; build/test41/41 PASS
41.98s e stesso candidato installato. Nessuna ricostruzione/header Apple alterato.
Restano lettore VM/immagini originali, slide/export/runtime/processo Apple/zero WSL.
Vedere DYLD_NATIVE_CACHE_LAYOUT.md e CURRENT_CHECKPOINT.md.

M6 loader dyld: collegamento nativo cache principale/subcache verificato sulla
subcache Apple originale .79.dyldlinkedit da1674805248 byte. UUID, VM offset e
geometria derivati dal principale; header figlio region0 invariato, SHA e immagine
APFS comune controllati. Confronto indipendente di entrambe le mappature e dei
record slide PASS. Build/install e41/41 test PASS40.61s. Restano altre subcache,
mappa combinata, immagini originali/runtime e processo Apple/zero WSL.
Vedere DYLD_NATIVE_SUBCACHE_CONTEXT.md e CURRENT_CHECKPOINT.md.

# Piano di correzione e completamento dell'architettura OPENFRUIT

M6 filesystem originale: attraversamento completo dei metadati sigillati e della
mappa del volume dalla CLI Windows installata PASS; 7656 nodi/493025 record,
8173 percorsi originali e 4577 extent. Tutti gli hash dei nodi e tutti i percorsi
coincidono con verifica indipendente. Release/install e 39/39 test PASS (40.28 s).
Localizzata shared cache originale;
lettura xattr/resource fork, decmpfs14 e dati/cache/runtime ancora da completare.
Nessun provider registrato o gate app/zero WSL superato. Vedi APFS_SEALED_TREES.md.

M6 filesystem originale: lettore metadati APFS Windows nativo PASS dalla CLI
installata, con SHA256 derivato dal producer AEA e lease stabile. Verificati
checkpoint XID24, sette header/checksum di oggetti effimeri, object map e volume;
confronto indipendente sull'immagine originale PASS. 39/39 test PASS (47.39 s),
Release/install PASS. Lettura file/extent/shared cache, closure/runtime/provider
e gate originali M6/app/zero WSL ancora aperti. Vedere APFS_NATIVE_METADATA.md.

M6 input originale: decifratura AEA completa Windows nativa PASS; 11 cluster,
2746 segmenti, padding verificati; LZFSE Apple originale invariato compilato
su Windows. Output 2.879 GB: SHA384 coincide con manifest e verifica indipendente,
risolvendo il mismatch del digest cifrato. 38/38 test PASS (47.97 s),
Release/install PASS. Input decifrato conservato in quarantena; filesystem,
provider/compatibilita/publisher e gate M6/app/zero WSL aperti.
Vedere AEA_FULL_DECRYPTION.md e checkpoint.

M6 crypto nativa: HPKE FCS originale e HMAC/root AEA verificati dalla CLI Windows
installata. Recuperata privatamente chiave 32 byte; root originale dichiara
2.879 GB decodificati, LZFSE, SHA256, segmenti 1 MiB/cluster 256. CFRG HPKE e
vettore root indipendente PASS, negativi rifiutati; 37/37 test PASS (56.52 s),
Release/install PASS. Cluster/decrittazione completa/digest/provider e gate
M6/app/zero WSL ancora aperti. Vedere AEA_NATIVE_CRYPTO.md e checkpoint.

M6 chiave FCS: recupero HTTPS WinHTTP derivato dai metadati AEA originali e
importazione PKCS8/P256 temporanea in Windows CNG. Redirect originale 301 verso
il CDN Apple verificato: un solo passaggio, host esatto/percorso chiave invariato.
CLI installata sul contenitore originale PASS; 37/37 test PASS (40.26 s),
Release/install PASS. Nessuna chiave persistita o stampata; autenticazione AEA,
HPKE/digest e gate M6/app/zero WSL ancora aperti. Vedere AEA_FCS_KEY_INPUT.md.

M6 AEA: lettore metadata Windows nativo collegato al report di quarantena e alla
CLI installata; hash sullo stesso handle protetto da scritture/sostituzioni.
Originale Apple 2.415 GB: header/metadati concordano con verifica indipendente;
forma FCS e URL chiave validati, nessuna autenticazione/decifratura o approvazione
digest. Release/install e 37/37 test PASS (43.94 s). Prossimo contratto: recupero
chiave nativo, HPKE e autenticazione AEA. M6/app/zero WSL aperti.
Vedere AEA_INPUT_METADATA.md e checkpoint.

Stato: esecuzione in corso, architettura non completata. Data: 2026-10-06.

M6 input grandi: streaming nativo <=16 MiB, CRC/SHA256/SHA384 incrementali,
quarantena nuova e binding dei componenti dalle identita' originali. Build/install
e 36/36 test PASS (39.87 s). Primo SystemOS originale da 2415919104 byte:
size/CRC/hash raw indipendenti PASS, digest del manifest NON coincide. AEA
originale trattenuto in quarantena per il decoder; complete=false/digest=false,
nessun provider o compatibilita' approvati, seconda variante non acquisita.
Prossimo contratto: AEA e dominio del digest. Vedere LARGE_RUNTIME_COMPONENT_INPUTS.md.

M6 consumer restore: libplist nativo legge entrambi i manifest originali sotto
un unico URL/ETag. CLI installata riproduce 180 identita' e 12966 componenti;
confronto indipendente di tutti i campi scalari/percorsi/digest PASS. Build/install
e 36/36 test PASS (38.13 s). Nessuna scelta arbitraria della variante SystemOS,
autenticazione o compatibilita' dichiarata. Vedere RESTORE_MANIFEST_INPUTS.md.

M6 membri metadata: lettore nativo bounded confronta header locale/ZIP64/nome/
dimensioni/CRC con directory e verifica stream stored/DEFLATE originale. CLI
installata su Restore.plist e BuildManifest.plist Apple PASS, hash/size coincidono
con i byte originali conservati. Build/install e 35/35 test PASS (41.98 s).
Acquisizione delle immagini grandi, autenticazione/AEA e runtime restano aperti.
Vedere ZIP_MEMBER_VERIFICATION.md.

M6 ZIP64: inventario nativo collegato al servizio range e alla CLI installata;
EOCD/locator/directory/extra dei membri derivati dai byte originali. Sul vero
IPSW Apple tutti i 1630 membri coincidono con l'inventario indipendente nei
sette campi originali, hash directory uguale. Build/install e 34/34 test PASS
(42.03 s). Estrazione/verifica dei membri, AEA e provider restano aperti.
Vedere ZIP64_RUNTIME_INVENTORY.md.

M6 acquisizione: HttpTransfer::ReadRange nativo Windows implementato, intervalli
64-bit bounded, ETag forte e If-Match per binding delle letture successive.
Rifiuta range/total/encoding/size/validator errati; cancel durante lettura PASS.
Build/install e 33/33 test PASS (40.28 s). Indice ZIP64 Apple originale letto
due volte dal servizio nativo, 169099 byte identici all'evidenza conservata.
Parser/estrazione ZIP64, AEA e routing acquisizione runtime ancora aperti.

M6 input di sistema: catalogo IPSW ufficiale Apple e manifest originali letti;
archivio ZIP64 da 26637307067 byte / 1630 membri. Header effettivi BaseSystem,
SystemOS e OS sono AEA1 profile 1; il grande DMG non cifrato e' RosettaOS.
Prossimo contratto: acquisizione selettiva ZIP64 nativa e decodifica AEA prima
di filesystem/shared-cache/closure. Nessun provider registrato, compatibilita'
o esecuzione Apple provata. Vedere DARWIN_SYSTEM_PROVIDER_INPUTS.md.

M6 ISA: backend CPU ARM64 compilato nativamente Windows da Unicorn 2.1.4 invariato,
hash sorgente fissato e 1032 file originali confrontati senza modifiche. DLL
isolata da zlib; codice Clang/LLD ARM64 originale con bind/rebase/argomenti restituisce
27, CLI zero-arg restituisce 18. Syscall assente e ciclo infinito respinti.
Suite 33/33 PASS (39.22 s), build/install e CLI installata PASS. Stage ARM64 sul
server Apple originale ora rifiuta i provider strong mancanti; non esegue Apple
ne' prova macro/consumer. Closure autentica, init/TLS/unwind/ABI/servizi e routing
produttivo senza WSL restano aperti. Vedere DARWIN_ARM64_EXECUTION.md.

M6 loader nativo: servizio Windows VirtualAlloc + risoluzione export/dipendenze
e applicazione bind/rebase formato 2/6, collegato a runtime map-image nella CLI.
Tre librerie Clang/LLD owned dimostrano puntatori reali in memoria, dati originali,
protezioni e rilascio; errori strong/legacy/comandi obbligatori/cancel respinti.
Suite 33/33 PASS (37.84 s), build/install e propagazione CLI installata PASS.
Server Apple originale ARM64 tramite comando installato: FAIL esplicito per
backend ISA assente, nessuna esecuzione/fixup Apple dichiarata riuscita.
Darwin init/TLS/unwind/ABI/servizi, provider autentici e ISA restano aperti.
Vedere DARWIN_NATIVE_MAPPING.md; M6 originale/app/zero WSL non completati.

M6 risoluzione simboli: lettore nativo export trie legacy/moderno implementato;
fixture Clang/LLD deriva offset del simbolo e identifica i suoi byte originali.
Suite 33/33 PASS (43.98 s), build/install PASS. Su 14 immagini Apple originali:
39132 record export, conteggi verificati indipendentemente con LLVM per ogni
immagine, hash invariati e CLI installata PASS. Non e' ancora binding/runtime;
indirizzi mappati, scritture fixup, provider/ABI/ISA e consumer originale aperti.
Vedere DARWIN_EXPORT_TRIE.md. Nessun gate complessivo M6/app/zero WSL superato.

M6 loader: catene originali di formato 2/6 percorse dal servizio nativo, con
limiti di pagina/segmento, ordinali, bit riservati e overlap controllati. Suite
33/33 PASS (59.60 s), build/install PASS. CLI costruita/installata su 14 originali
ARM64: 9835 posizioni bind e 25354 rebase, hash invariati. Scritture dei fixup,
risoluzione degli indirizzi, provider runtime e ISA ancora aperti. Nessun gate
esecuzione/app/zero WSL superato. Vedere DARWIN_POINTER_CHAINS.md.

M6 avanzamento corrente: lettore nativo dei metadati chained fixups collegato
all'ispezione Mach-O, suite 33/33 PASS (38.89 s), build/install PASS. Su 14 immagini
originali invariate: 7898 import e 27 tabelle segmenti con pointer format 6.
Nessuna applicazione dei fixup o esecuzione originale; i sei provider strong
mancanti restano tali. SwiftCore macOS estratto dall'archivio e' x86_64 e non
soddisfa il server ARM64. Dettagli in DARWIN_CHAINED_FIXUPS.md e checkpoint.
Estrattore e risoluzione dei percorsi sono implementati; closure runtime,
mapping/bind/rebase, ABI e ISA restano da completare. I paragrafi di avanzamento
sotto conservano i risultati delle iterazioni precedenti, non lo stato finale.

M6 input originali: inventario XIP nativo con comando CLI archive-members,
metadati/partner CPIO, budget/cancel/checksum e propagazione PASS; suite 33/33
(39.13 s), install PASS. Archivio Xcode autenticato letto integralmente: 156950
membri, integrita'/firma/catena/revoca verificate; sei server originali individuati.
I sei header dichiarano thin ARM64; il processo host Windows e' x86_64. E' un
requisito ISA della sorgente selezionata, non una prova completa dei binari o
della causa precisa dell'handshake legacy. Estrattore generico, namespace/closure,
esecuzione ISA e loader/ABI ancora da completare. Nessun gate macro/app/zero WSL.
Dettagli e limiti in XIP_RUNTIME_INPUT_INVENTORY.md.

M6 metadata nativi: nuovo modulo openfruit_darwin collegato al preflight del macro
host. Slice CPU, dipendenze/RPATH/segmenti/piattaforma e hash derivati dai binari;
Clang/LLD owned, FAT/corruzioni/concorrenza e 13 plugin originali nel processo host
PASS. Suite 33/33 (40.94 s), install e host installato PASS. Inventario nativo:
31 nomi diretti / 25 forti, nessuna prova closure/ABI/esecuzione. Il servizio resta
loaded=false e senza backend; routing WSL produttivo e guasto originale aperti.
Input server/runtime autorevoli e loader/ABI sono il prossimo contratto M6.
Vedi DARWIN_IMAGE_PREFLIGHT.md; nessun gate macro originale/app/zero WSL superato.

Risoluzione binaria: recovery trova shared-cache/artifacts senza estensione ZIP,
lega URL/checksum ai manifest valutati da SwiftPM, verifica SHA-256 e respinge
ownership ambigua. Estrattore riconosce formato dai byte. Servizio produttivo su
fixture owned con resolve ufficiale PASS; suite 32/32 (37.77 s), install PASS.
Dettagli/limiti in BINARY_ARTIFACT_RECOVERY.md. Nextcloud originale, stesse dimensioni
e cache, supera resolve senza invocare recovery e compila molte dipendenze; exit 1
su NextcloudKitUI: handshake server macro Apple fallito per #Preview originale.
Nessun gate app/IPA o zero WSL. Prossimo contratto M6.1/runtime nel checkpoint.

M5 packaging unsigned: servizio PackageUnsigned esplicito collegato a CLI package;
assembly indipendente, risorse prodotte preservate, ZIP completo e pubblicazione
atomica prima del risultato, nessuna firma/preparazione credenziali nel servizio.
Prove di contenuto archivio/identita'/errore e CLI intent PASS; suite 31/31 (28.74 s),
build/install PASS. Fixture stage sentinel non prova compilazione/Mach-O. Bootstrap
opzionale/firma/modularizzazione restano aperti. Nextcloud originale ripreso con
package, Debug, SDK 26.5, Swift 6.3.3, jobs 15: exit 1 in risoluzione SwiftPM
binaria (I/O 514 e timeout download), prima di compilare l'app. Cache archivio
osservata in shared-cache/artifacts non coperta dall'indice recovery corrente.
Nessun gate app/IPA superato; prossimo esperimento nel checkpoint.

M1 provider condiviso: shutdown/restart Darling eliminati da bridge e adapter WSL.
Bridge reale su fixture owned: retry del solo server, errore esplicito, processo
indipendente/file lock preservati, distribuzione configurata/default PASS. Suite
30/30 (28.02 s), build/install e bridge installato PASS. Nessuna prova Linux/plugin
originale/zero WSL; allowlist e dispatch generico restano aperti. Nextcloud pulito,
vecchi prodotti conservati fuori upstream, Swift 6.3.3 ripristinato e inspect Debug
PASS. Contratto package unsigned successivamente corretto e ripresa osservata sopra.

M2 linker SDK: eliminato il riuso dell'overlay legacy basato solo su usr/lib;
il servizio restituisce esclusivamente l'SDK originale selezionato. Cache legacy
preservate ma mai usate per sostituire/recuperare SDK assenti. Prove negative owned
PASS, policy unmodified-sdk-v2 per gli artefatti dipendenti; suite 29/29 (28.53 s),
build/install PASS. Gate strong/weak attraverso l'applicazione ancora aperto.

SDK autentico iOS 26.5 ripristinato con comando nativo: login aggiornato,
catalogo/download indipendenti, firma/integrita' XIP, estrazione, pubblicazione e
registrazione PASS. Registrazioni con target positivamente assente ora riparabili;
installazioni presenti/incomplete restano protette. Suite 29/29 (27.54 s), install
PASS. Nextcloud non ancora ricompilato; gate complessivo e zero WSL restano aperti.

Servizio SwiftPM di workspace indipendente verificato: grafo ufficiale -> view
Git -> SwiftPM compile/link/run (17), originali preservati anche su errore e
cancellazione; nessun marker ready su fallimento. Suite 29/29 (26.67 s), install
PASS. Prova host Windows Swift 6.4, distinta da Nextcloud congelato. NON ancora
collegato a BuildNativePackage; local/registry esterni, lease, cache e integrazione
restano aperti. Il percorso produttivo materializza ancora i checkout.

M4.1 producer della view esterna implementato e verificato su checkout Git owned:
header/sorgenti/risorse/directory, catene, Unicode, include relativi consumati da
Clang reale; nessun hard link. Cicli, root escape, target mancanti, cancellazione
e deadline impediscono la pubblicazione. Suite 27/27 (14.36 s), build/install PASS.
Main collegato al workspace esterno prima della discovery, materializzatore
applicativo rimosso; prodotti/intermedi fuori upstream. Resolver header ora usa
identita' Git, mai contenuti brevi. Propagazione metadata Xcode -> sorgenti e
packaging e cancellazione durante Git reale PASS. Suite 28/28 (15.04 s), install
PASS. SwiftPM ancora da migrare: zero-touch completo NON provato; rimangono
phase/input/cache identity e gate originale. Scope in GIT_SOURCE_VIEW.md.

M1 controllo CLI: Ctrl+C/Ctrl+Break raggiungono il controllo nativo condiviso,
processi owned terminati/raccolti, exit 130 e stato cancelled in normale/JSON.
Segnali reali su console owned nascoste, lock rilasciato e singolo evento;
baseline installata FAIL, candidato PASS. Suite 26/26 (13.28 s), installazione
e controlli CLI reali PASS. Adapter, cooperazione in-process e full app ancora
aperti; non dichiarare completo M1. Firma resta rinviata per priorita' utente.

Priorita' utente aggiornata: rinviare la firma e proseguire con ripristino e
architettura. 58/58 snapshot recuperati verificati contro gli hash, 404/404
file della baseline presenti; nessun sorgente perso individuato. Inventario
dei gate realmente mancanti in RECOVERY_RECONCILIATION.md. Tentativo signer
non validato conservato fuori dal repository, non nel candidato.
M1: stream JSON CLI e journal ora condividono schema/producer/timestamp/PID/TID
e sequenza, redazione comune e correlazione span. Concorrenza/replay e CLI
installata PASS; suite 25/25 (13.19 s). Restanti gate M1 e M0–M8 ancora aperti.

Ultimo avanzamento: producer/verifier nativo CodeResources per bundle iOS piatti,
hash streaming, link fisici e inventario indipendente; firma del figlio prima
del sigillo genitore verificata su Mach-O arm64/x86_64 di stage. Alterazione del
figlio respinta dal genitore. Fixture di estensione completata con il nome del
proprio eseguibile. Suite 25/25 PASS (11.67 s), candidato installato e smoke PASS.
Packager produttivo, selezione profili, pubblicazione atomica, IPA e zero WSL
restano aperti; dettagli e limiti nel checkpoint e SIGNER_INPUT_CONTRACT.md.

Ultimo avanzamento: flag execSeg derivati automaticamente dallo XML sigillato
e dal tipo Mach-O; tutte le mappature booleane e propagazione debug dal profilo
provate su arm64/x86_64. CMS autentico non nasconde flag incoerenti. Dylib reali
senza bit main; 24/24 PASS (11.46 s), candidato installato. Risorse, policy/profili
completi, packager, IPA e zero WSL restano aperti; dettagli nel checkpoint.

Avanzamento precedente: conversione DER versione 1 e lettore indipendente tipizzato,
producer atomico degli slot XML/DER 5/7 per app/estensione, consumo obbligatorio
nella firma Mach-O nativa. Vettori ASN.1, range signed, forme malformate, limiti
e cancellazione PASS; 24/24 (11.34 s), candidato installato. Non prova AMFI,
risorse/profili completi/packager/IPA o zero WSL. Checkpoint e contratto aggiornati.

Avanzamento precedente: writer/lettore ricontrollano CMS e richieste tipizzate,
ricostruiscono i valori del profilo e richiedono il blob XML esatto. Identita'
alterate, default rimossi, bool convertiti in interi e grants non richiesti
respinti anche con blob coerente all'alterazione. 23/23 PASS (12.09 s), candidato
installato e smoke PASS. DER/risorse/trust/packager/IPA restano aperti.

Avanzamento precedente: writer e lettore nativi della firma Mach-O in memoria,
resize LC_CODE_SIGNATURE/LINKEDIT prima degli hash, SuperBlob/CMS e slot
verificati sul risultato arm64/x86_64. Firma ripetuta/in-place e alterazioni
negative PASS; layout VM sovrapposto respinto. Suite 23/23 PASS (12.06 s).
Non prova producer CodeResources/DER, trust, packager o IPA. Dettagli nel checkpoint.

Avanzamento precedente: Mach-O reali Clang/LLD arm64 e x86_64 -> generazione
CodeDirectory da load commands -> verifica pagine/slot e CMS nativo: PASS.
CodeDirectory originali LLD verificate; hash ricalcolati separatamente, alterazioni,
input malformati, cancellazione/deadline respinti. Suite 23/23 PASS (12.21 s).
Mancano pubblicazione della firma/layout, risorse/DER, consumo nel packager,
copertura formati completa e gate applicativi. Dettagli nel checkpoint.

Avanzamento 2026-10-04: CodeDirectory di stage -> CMS nativo con attributi Apple
derivati dai byte e binding bundle/team/profilo; decodifica e ricalcolo separati
PASS, 23/23 test. Restano generazione/verifica Mach-O, risorse, DER, consumo nel
packager e i gate del piano; non equivale a firma completa o IPA valido.

Avanzamento precedente: primitiva CMS detached nativa sulla credenziale effimera,
verifica separata di contenuto/attributi/certificato e input malformati: 23/23
test PASS. Non provava CodeDirectory, firma Mach-O o consumo nel packager;
il relativo provider M3 resta da completare. Stato corrente nel checkpoint.

Ripristino: recuperato il piano originale insieme al codice/test/documenti
precedenti, comprese le modifiche non committate sulle estensioni. Gli
identificativi e le misure storiche sotto descrivono il lavoro precedente,
non commit recuperati nella copia attuale. Nuova build 23/23 PASS e test Mach-O
5/5 PASS; dettagli in RECOVERY_REPORT.md e CURRENT_CHECKPOINT.md. Il gate
applicativo e zero WSL restano non superati.

Avanzamento verificato: baseline preservata e checkpoint corretto (`e3545a8`);
flag JSON Clang incompatibile rimosso e provato sul proxy reale (`30ef062`);
stream JSON CLI separato dall'output umano, journal mantenuto e redazione
condivisa (`0cc4f6c`). Suite nativa 18/18 PASS. M0/M1 sono ancora parziali:
non equivalgono al gate applicativo né a zero WSL. Inventario iniziale M6.1:
13 librerie plugin FAT Mach-O, slice x86_64/arm64 e 31 dipendenze dirette;
esecuzione nativa e closure transitiva non ancora provate. Telemetria candidata
`447525b`: decoder stderr bounded, CRLF Windows verificato con Swift reale,
eventi job/inputs senza percentuali inventate; 19/19 test PASS. La riproduzione
Nextcloud si ferma al SDK registrato con junction dangling: prova applicativa
telemetria ancora mancante. SDK autentico richiesto, nessun bypass introdotto. Supervisore Run:
Job Object scoped, child sospeso/assegnazione verificata, handle allowlist,
cancel/deadline, discendenti/lock e output bounded provati; 20/20 test PASS.
M1 resta parziale: cancellazione console/app in-process/adapter
ancora da completare, prova applicativa in attesa del SDK autentico. Capability schema 2:
inventario read-only senza WSL/bootstrap/migrazione credenziali, prerequisiti
mancanti e contratti unsupported espliciti, snapshot JSON propagato; 21/21 test
PASS. Presenza strumenti non equivale a esecuzione o gate IPA valido. Operation control:
cancellazione/deadline condivise fra span/worker e propagate automaticamente a
Run, isolamento fra operazioni concorrenti e sinkless deadline verificati;
21/21 test PASS. Candidato installato nell'entrypoint standard e smoke dei proxy/
capability PASS; console/adapter e lavoro in-process restano da completare.
M2 input SDK: enrichment Photos eliminato, overlay VFS legacy non riusati,
flag overlay omessi se assente; cache SwiftPM/moduli versionate per input SDK
originali. Discovery managed con fixture SDK e overlay legacy verificata;
21/21 test PASS. Il SDK autentico mancante impedisce ancora la riproduzione
Nextcloud: contratto locale verificato, gate applicativo non superato.
M2 App Group: generatore swizzling, API interna e input automatico del linker
rimossi; assenza dei selettori/path verificata nel candidato installato, suite
21/21 PASS. Vecchi eseguibili/IPA non validi come gate; relink reale e verifica
provisioning per bundle ancora da provare dopo il recupero del SDK autentico.
M2 link: dynamic_lookup globale rimosso; flag espliciti OTHER_LDFLAGS conservati.
Esperimento causale con linker reale conferma FAIL strong mancante senza policy
permissiva, PASS con essa e weak load/reference corretti con provider presente.
È prova di componente con comando manuale, non regressione della pipeline.
21/21 test PASS; progetto controllato via OPENFRUIT e target Nextcloud restano
obbligatori prima di dichiarare il contratto completo.
M6 protocollo: falso loaded/expanded eliminato dal macro host; JSON strutturato,
diagnostiche protocollo 7, limiti frame e nessuna feature loader non implementata.
Baseline host preservato FAIL; candidato installato PASS anche con consumer Swift
reale isolato; suite 22/22 PASS. Nessun runtime Darwin eseguibile implementato e
nessun gate originale plugin/zero WSL superato. Vedi MACRO_HOST_PROTOCOL.md.
M6.1 diagnostic closure: ownership dei RPATH ereditati corretta, LC_ID_DYLIB
riconosciuto dai metadati, dichiarazioni provider senza file non accettate e nessun
match di cache per basename soltanto. Baseline FAIL, 5/5 contratti diagnostici PASS.
LLVM sui 13 plugin reali, senza WSL: 31 path di dipendenza, 25 nomi forti non risolti
nella view Windows corrente. Closure transitiva ed esecuzione nativa NON provate.
M3 preflight necessario: firma CMS attached verificata, application-id/prefix
confrontati con CFBundleIdentifier effettivi di app/appex prima di signer/password.
Test CMS alterato, wildcard e nested identity PASS; profilo Hello configurato
respinto contro Info.plist invariati dall'IPA Nextcloud baseline. Suite 23/23 PASS.
Non prova trust Apple, eligibility, entitlements, profili distinti o IPA valido;
questi gate e la riproduzione applicativa restano da completare.
Propagazione M3: discovery pbxproj/xcconfig -> packaging reale -> mismatch
respinto prima dei prerequisiti password/processi, evento failed verificato;
23/23 PASS (11.21 s). Input di stadio sentinel, non prova Mach-O/full-app.
Il profilo Hello fornito è intenzionalmente di test: incompatibilità con gli ID
upstream attesa, non un difetto del profilo. Non autorizza un gate IPA valido.
M3 root entitlements: CODE_SIGN_ENTITLEMENTS/configurazione propagati da metadati
Xcode al preflight nativo; un App ID corrispondente non nasconde App Group
non autorizzati. Test packaging reale senza binding/path pre-risolti PASS,
template invariato, errori prima di signer/password; suite 23/23 (11.32 s).
È controllo necessario della view plist iOS, non firma/verifica IPA: trasporto
entitlements al signer, estensioni, profili per bundle e authority DER mancanti.
M3 estensioni: propagazione target/configurazione/template al prodotto e al
packager verificata con metadati owned e input fisici di stage; diritti child
distinti, metadati assenti/ambigui, target errato, prodotto mancante, collisione
e bypass tramite risorse respinti. Suite 23/23 PASS (11.13 s), candidato CLI
invariato. Non prova compilazione AppBuilder/Nextcloud né firma valida.
Dettagli: PROVISIONING_IDENTITY_PREFLIGHT.md e architecture-completion/extension-metadata.

M3 richieste per bundle: XML espanso e snapshot CMS verificato conservati dal
servizio nativo e dal packager, senza copiare grants aggiuntivi o pubblicare
insiemi parziali. Profilo di altra identita' rifiutato anche senza application-id
nel template. Suite 23/23 PASS (11.55 s); restano default di piattaforma,
selezione profili e consumo effettivo del signer, DER/trust e verifica IPA.

M3 input di firma dal profilo: identita' fisica/prefix, team coerente con
DEVELOPMENT_TEAM, keychain di default per bundle e valori debugger/TestFlight
ora preparati separatamente dalle richieste esplicite. Configurazione senza
file entitlement scoperta dai metadati e provata su root/estensione; subset
keychain e diritti child preservati, grants extra/wildcard non copiati.
Suite 23/23 PASS (12.09 s), candidato installato e smoke PASS. Non prova
consumo del signer, base input autentici/CODE_SIGN_INJECT_BASE_ENTITLEMENTS,
DER/trust/eligibility, profili separati o IPA valido. Vedi SIGNER_INPUT_CONTRACT.md
ed evidenze architecture-completion/profile-signature-inputs.

M3 credenziale/certificato: P12 importato in memoria senza persistere chiavi,
identita' singola, date e possesso della chiave verificati con CMS detached.
Certificato effettivo confrontato con DeveloperCertificates dallo snapshot CMS
per ogni app/appex prima del processo signer. Password errata, certificato non
autorizzato, PFX ambiguo/senza chiave e certificati fuori validita' respinti;
output stale cancellati e password pulita anche sui return anticipati.
Propagazione al packager reale con P12/DPAPI owned PASS; suite 23/23 (11.60 s),
installazione e smoke PASS. Non prova che il signer consumi tale identita':
riletture dei path, password in argv, trust/DER, eligibility completa e firma
IPA restano aperti. Evidenze architecture-completion/certificate-binding.

Baseline sorgente esaminata: `1a272e3e2270a41a2407c6f158539e524cb1d1d6`.

Questo documento consolida i lavori mancanti di ARCHITECTURAL_PLAN.md e MODULAR_ARCHITECTURE_PLAN.md. Non dichiara completate le loro milestone. AGENTS.md, OBJECTIVE.md e DIAGNOSTIC_PROTOCOL.md rimangono vincolanti. CURRENT_CHECKPOINT.md deve indicare il singolo esperimento attivo durante l'esecuzione del piano.

## 1. Risultato richiesto e vincoli

- Prodotto Windows-native: zero invocazioni WSL/Darling su Linux, zero dipendenza da Hyper-V/Linux/VHDX in installazione, bootstrap, inspect, capabilities, build, package, sign e device operations supportate.
- Esecuzione delle macro/plugin originali. Nessuna espansione sostitutiva, risposta di successo simulata o logica selezionata dal nome di app/package/plugin.
- Upstream, SDK, manifest e plugin invariati. Nessuna dichiarazione Apple sintetica tramite VFS e nessuno swizzling applicativo per compensare provisioning incompleto.
- Entrypoint `%LOCALAPPDATA%\OPENFRUIT\bin\OPENFRUIT.exe`; launcher PowerShell limitato all'inoltro degli argomenti. `.tools` assente.
- SDK/toolchain/cache gestiti sotto LocalAppData; configurazione, segreti e stato utente sotto `%USERPROFILE%\.OPENFRUIT`.
- Macro/plugin N=2. Compilatore, SDK, deployment target, configurazione, architettura e provider congelati per ciascun esperimento.
- Gate intermedio: IPA correttamente firmato e autorizzato per ogni bundle. Installazione/lancio restano obiettivi di prodotto, da attivare come gate applicativo soltanto tramite checkpoint.

La presenza di un eseguibile PE o il superamento dei 17 test attuali non dimostra il risultato. Le vecchie promesse di 2 ms, 1 ms, 0 ms o conformità 100% vengono sostituite da misure riproducibili e contratti verificati.

## 2. Stato iniziale e prove da conservare

- Candidato installato esaminato SHA-256: `523618604FB860C50C5B86B32E21BBE543E5929E03AF0594FD4792C4B6642771`; non assumere che equivalga a una nuova compilazione della baseline sorgente.
- Nextcloud upstream: `b2f5ad8233b7f7460299add458b4b0b36ea73d24`; stato osservato: solo `?? build/`, nessun diff tracked. Non chiamarlo checkout completamente pulito.
- Build osservata: Debug, arm64-apple-ios17.0, iPhoneOS 26.5, Swift 6.3.3, jobs=15; N=2 è il default del codice, non una misura registrata del vecchio run.
- IPA SHA-256: `1094433446ff66ef452ba833ad161114333a232b67c9992f29869cd7164890e7`.
- Journal: `%USERPROFILE%\.OPENFRUIT\diagnostics\build-events\5d64b5e593a6faca709a5636a876f851\events.jsonl`.
- Pipeline terminata in 1862203 ms, con riuso package SwiftPM. Provisioning FAIL: bundle Nextcloud firmati con identità Hello; App Group upstream assenti. I controlli hash delle CodeDirectory eseguiti non equivalgono alla verifica completa CMS/risorse/provisioning.
- Difetti riprodotti: host macro con espansioni vuote senza plugin; JSON Clang che cambia PASS in FAIL; simbolo forte mancante accettato con dynamic_lookup.
- Telemetria: parser su stdout, eventi Swift osservati su stderr; zero compiler.began/finished nel journal. OpenIB: 128 task UI, nessun processo openib.exe, 2–41 ms per task.

Durante l'attuazione preservare baseline/binario/IPA originali in area diagnostica senza segreti, con hash e manifest. Registrare anche tool identities, commit, configuration, scheme/target IDs, architecture, provider, SDK identity, jobs, N, cache schema e artifact identities. La mancanza di profili corretti è una dipendenza utente da segnalare, mai da aggirare.

## 3. Sequenza di lavoro e dipendenze

Ogni riga è una milestone con commit e candidato autonomi. Le sottounità devono rimanere separate quando cambiano contratti differenti.

| Ordine | Milestone | Dipendenze | Gate di uscita |
|---|---|---|---|
| M0 | Evidenza, checkpoint e capability veritiere | Nessuna | Stato riproducibile, provisioning FAIL documentato, capacità non implementate dichiarate |
| M1 | Diagnostica e supervisione affidabili | M0 | JSON equivalente, eventi Swift reali, cancellazione e process tree verificati |
| M2 | Ripristino semantiche SDK/runtime/link | M1 | Nessun header sintetico/swizzling; simboli forti mancanti FAIL; weak preservati |
| M3 | Firma per bundle e verifica IPA indipendente | M0/M1, M2 prima del gate app completo | Profili/entitlements coerenti; artefatti alterati respinti |
| M4 | Zero-touch filesystem, grafo e cache | M1; M2 per identità SDK definitive | Nessuna modifica tracked durante build; invalidazione corretta; DAG reale |
| M5 | Contratti modulari e orchestrazione condivisa | M1–M4 | CLI sottile; dipendenze enforceable; stesso servizio usabile da CLI/IDE |
| M6 | Provider nativi e rimozione completa WSL | Inventario M0; contratti M1/M5 | Plugin originali, shell phase, SwiftShims e SVG senza WSL |
| M7 | Risorse e device services completi | M1/M5; M6 per assenza WSL | Diagnostiche tipizzate e backend device nativo verificati |
| M8 | Performance, distribuzione e gate finale | M2–M7 | IPA valido, matrice reference, package release verificato, zero WSL dimostrato |

L'inventario e la prova di fattibilità del runtime M6.1 iniziano subito dopo M0, prima di grandi refactoring. Il runtime nativo è il principale rischio tecnico: non rimandare la scoperta di dipendenze mancanti alla fine. L'ordine non autorizza a correggere sintomi downstream durante una diagnosi con un errore causale precedente aperto.

## 4. M0 — Evidenza e verità dello stato

1. Riscrivere CURRENT_CHECKPOINT.md in forma breve: ultima pipeline completata, provisioning FAIL, dimensioni note/ignote, cache riusata, prossimo esperimento permesso. Conservare storia e report separatamente.
2. Correggere le dichiarazioni di completamento di ARCHITECTURAL_PLAN.md, MODULAR_ARCHITECTURE_PLAN.md e README, distinguendo implementazione, prova del componente e prova del percorso reale.
3. Capability discovery basata su implementazioni e prerequisiti verificati: implemented/unavailable/unsupported. Un comando in help non basta. Eliminare probing WSL dall'adapter finale; non avviare tool durante inventario read-only senza necessità.
4. Preservare candidate identity senza sovrascrivere silenziosamente baseline/installazione usata per il confronto.
5. Inventariare tutti gli avvii processi Windows e indiretti: macro bridge, provider Swift Linux, shell phases, SVG rasterizer, bootstrap, capability probe e device tools. Registrare formati/CPU/dependency closure delle librerie, senza esportare contenuti proprietari o segreti.

Gate: manifest di evidenza completo per un run controllato; risultati legacy non etichettati come nuova architettura completata.

## 5. M1 — Diagnostica e processi

### M1.1 Stream e compiler adapters

- Un solo renderer console e un solo protocollo machine-readable, con sink multipli per stream e journal. I domini emettono eventi tipizzati; non scrivono direttamente su stdout.
- Collegare il decoder Swift al canale effettivo; riconoscere framing length-prefixed, chunk parziali, record malformati e output testuale. Conservare errori senza bloccare il draining. Nessuna deduzione di eventi da testo arbitrario tra parentesi graffe.
- Whole-module/batch: mostrare gruppo, input e fasi osservate; per-file solo se il compilatore lo fornisce. Non incrementare sorgenti completati per emit-module e non trasformare un failed compile in completamento di tutte le unità.
- CPU/RAM associate ai PID posseduti dalla task, con aggregazione esplicita e campioni datati. ETA soltanto stimata; assenza di eventi significa progresso indeterminato.
- Rimuovere l'imposizione di un formato Clang non supportato. Usare un adapter capability-aware per diagnostiche realmente disponibili; implementare consumo .dia/Fix-It ove supportato. Lo schema interno non deve dipendere dall'esistenza di JSON nativo nel tool.
- Event envelope versionato con operation/task/span, correlazione producer, sequenza, timestamp, stato terminale e artifact references; redazione prima di persistence/transport. Limiti di coda/output, replay e errori logging espliciti.
- Crash/exception correlati al processo/task con codice, module identity e simboli matching; stack disponibile/unsymbolicated/unavailable esplicito. Nessuna stack inventata da exit code. Memory dump solo opt-in protetto, mai esportato automaticamente.
- Separare JSON Lines da LSP. Prima completare il protocollo operation adapter documentato; aggiungere LSP solo con messaggi e capacità implementati.

Test: due invocazioni del medesimo piccolo progetto attraverso CLI normale/JSON con esiti identici; ogni record JSON valido; errore compiler con posizione e note; WMO e parallel compile senza conteggi inventati; stream chunked/malformato/backpressure. Percorso Nextcloud deve produrre eventi reali per i compilatori realmente avviati.

### M1.2 Process supervisor

- Contratto Run con OperationContext, cancellation token, deadline e child environment immutabile.
- Job Object per operazione, RAII; creare figlio sospeso, verificare configurazione e assegnazione, poi ResumeThread. Se il contratto non può essere garantito, errore esplicito e terminazione del figlio.
- Handle inheritance allowlisted; nessun figlio posseduto può uscire dal job involontariamente. Supportare nested job secondo l'ambiente host con prove reali.
- Cancellazione: stato cancelling/cancelled, terminazione e raccolta dei figli, draining bounded, rilascio file/temp/leases. Non trattare cancelled come normale errore compiler.
- Nessun shutdown globale di WSL/Darling per la migrazione. Eventuali esperimenti legacy restano isolati, senza interferire con sessioni non possedute.

Test: helper OPENFRUIT-owned genera figlio/nipote e mantiene file aperto; cancel/deadline/failure verificano terminazione, rilascio lock e stato terminale. Ripetere in contesto CI/nested job. Nessuna interruzione dei processi dell'utente.

## 6. M2 — SDK, runtime e link

### M2.1 Input immutabili e semantiche originali

- Eliminare enrichment PHPhotoLibrary.h e invalidare gli overlay/moduli influenzati. VFS consentito per rappresentare path/symlink/case semantics con stessi contenuti, mai per inventare API.
- Rimuovere App Group swizzling dalla pianificazione/link. Invalidare tutti gli eseguibili interessati: riuso di oggetti non modificati solo se indipendenti dal contratto.
- Audit del runtime Swift compat: usare upstream runtime/builtins autentici, selezionati per toolchain e deployment. Non soddisfare force-load o entrypoint ABI con oggetti che nascondono una dipendenza assente. Ogni bridge ABI deve essere genericamente corretto e testato, non un no-op.
- Riprodurre il target realmente interessato con SDK 26.5 congelato. Se mancano API richieste da upstream, registrare incompatibilità e fermarsi. Un SDK ufficiale adeguato apre una nuova diagnosi; non cambiare SDK e toolchain silenziosamente per ottenere PASS.

### M2.2 Link contract

- Togliere dynamic_lookup globale; derivare OTHER_LDFLAGS e altri setting dal progetto. Conservare policy esplicite valide quando richieste dai metadati, senza fallback automatici che nascondano input mancanti.
- Verificare framework/library/module propagation, autolink e XCFramework slice selection per piattaforma/CPU. Nessun path manuale nel test di propagazione.
- Separare weak linking/availability dalla risoluzione permissiva. Il simbolo Photos dell'IPA vecchio è weak; non usarlo come prova di una missing strong reference.

Test: progetto controllato con simbolo forte mancante deve fallire tramite OPENFRUIT; riferimenti weak e deployment target corretti devono conservare semantica attesa; dipendenza reale derivata dal grafo deve raggiungere compiler/linker automaticamente. Poi target originale, fermandosi al primo errore nuovo.

## 7. M3 — Signing e verifica del gate

- Separare packaging, profile selection, signing e verification in contratti distinti.
- Propagare CODE_SIGN_ENTITLEMENTS valutato e identità target per ogni app/appex/framework firmabile. Entitlements derivati dall'upstream/configurazione esplicita e autorizzati dal profilo; non sostituirli con quelli del profilo Hello.
- Selezionare profilo per bundle ID/platform/team/certificate/device/distribution/expiry/capabilities. Rifiutare prima della firma combinazioni incompatibili. Se mancano profili corretti, segnalarlo come dipendenza utente.
- Firmare nell'ordine corretto i bundle annidati; profili dove richiesti; non riutilizzare application-identifier del contenitore per tutte le estensioni.
- Verificare DER-Encoded-Profile moderno oltre alla view plist legacy: identità, grants e certificati devono concordare con la fonte autorevole del device.
- Verificatore indipendente dalla risposta zsign: CodeDirectory/CMS/trust secondo policy, hash pagine e special slots, CodeResources incluse nested signatures, provisioning/entitlements/bundle IDs. Non dichiarare completo il gate se una parte è unavailable/unverified.
- Protezione DPAPI, secret references e redazione restano obbligatorie. Valutare trasporto credenziale al signer senza esposizione non necessaria nella command line; nessun segreto in fixture/journal.

Test: profilo Hello contro bundle Nextcloud deve essere rifiutato prima della firma; fixture senza identità/manual override hardcoded quando la derivazione è sotto test; dati firmati alterati intenzionalmente respinti; verifica separata di tutti i bundle del prodotto reale. Profili/certificati del run finale sono input utente, non file committati.

## 8. M4 — Filesystem, DAG e cache

### M4.1 Zero-touch e path

- Sostituire materializzazione/ripristino dei placeholder upstream con view esterna per tutti i tipi: header, sorgenti, risorse e directory. HeaderMap/VFS/path mapping devono riflettere identità Git e target, senza scrivere nei checkout.
- Non risolvere come symlink ogni file breve somigliante a un path; usare metadata Git autorevoli. Gestire catene, cicli, escaping dal root, nomi duplicati e mapping ambiguo esplicitamente.
- Build intermedi fuori dal checkout. Prima del gate reale `git status --porcelain` completamente pulito; non aggiungere ignore per nascondere output fuori architettura. Migrazione controllata del vecchio build/ preservando IPA/evidenze, senza pulizia distruttiva indiscriminata.
- Uniformare extended paths, UNC e case semantics nei filesystem adapters. Testare SDK/view su volumi supportati con e senza case-sensitive directories; non riscrivere SDK per ottenere case behavior.
- Launcher di produzione solo forwarding a LocalAppData; launcher diagnostici espliciti separati. Nessuna impostazione .openfruit-fork implicita nel prodotto.

Test: osservare contenuti/tipo/hash/status dei file upstream prima, durante, dopo successo/failure/cancel; non basta diff finale. Include symlink non-header, directory, collisioni e long paths/Unicode/UNC.

### M4.2 Grafo reale

- Identità node = progetto autorevole + target UUID + platform/configuration/architecture; mai solo nome visualizzato.
- Costruire e validare il DAG prima dell'esecuzione. Collegare BuildGraph alla pipeline reale oppure sostituirlo con un unico scheduler documentato; niente secondo grafo morto accanto alla ricorsione.
- Target dipendente assente, ciclo e selezione ambigua sono errori espliciti. Schemes/configuration/xcconfig/settings e phase ordering determinano il piano.
- Dichiarare input/output, generazioni di header/moduli/risorse e relazione producer-consumer; invalidazione dipendente e first causal error centralizzati.

Test: target omonimi in subproject, ciclo, dipendenza mancante e producer generato; fixture derivano tutte le informazioni dal progetto.

### M4.3 Identità, storage e invalidazione

- ArtifactKey versionato: compiler/linker/resource-tool identity, SDK content/manifest identity, deployment triple, configuration, architecture, flags semantici, graph revision, provider/runtime/plugin identities e contenuto degli input rilevanti, inclusi package locali.
- Separare immutable downloads da mutable build caches. Per gli oggetti runtime includere compilatore/SDK e source identity; non validare solo uno stamp fisso e il path.
- Metadata/artefatti pubblicati atomicamente, lock/lease per producer concorrenti, checksum e commit marker scritto solo dopo completezza. Cache incomplete/corrotte respinte; cache hit/miss con ragione.
- Retention, prune e recupero crash bounded, fuori dai checkout; non rimuovere artefatti in uso.
- Import recovery: index dei candidati che preserva ambiguità e ownership, cache anche di esito vuoto/errore con policy dichiarata; single-flight per richieste identiche, invalidazione sostituzioni same-path e nessun lock permanente dopo crash. Misurare extractor count/I/O e riprodurre il modulo originale senza -F/-I manuali.
- Hard link solo per input/artefatti immutabili; evitare che un write attraverso alias alteri upstream/SDK. Copy fallback cross-volume. SHA-256 resta accettabile: BLAKE3 si valuta con benchmark e vantaggio provato, non per inseguire una promessa.

Test: modificare sorgente package locale, compilatore/SDK/flags/architecture/configuration; ricostruire soltanto la closure coinvolta; delete/corrupt/partial publish e parallel access; reuse unrelated warm products consentito.

## 9. M5 — Architettura modulare completata

Direzione finale delle dipendenze:

```text
CLI / future IDE / operation adapter -> application services
application -> project, environment, sdk, dependencies, build,
               resources, packaging, signing, devices
SDK acquisition / signing -> credentials
domain services -> shared immutable contracts, artifacts, foundation
domain services -> event sink contract -> observability implementations
resources -> openib_core
host providers -> foundation/artifacts; nessuna conoscenza dell'app
```

- BuildRequest/BuildContext immutabili: snapshot progetto, frozen identities, configuration, SDK/deployment distinti, toolchain/CPU, provider, resource limits, cache namespace e secret references.
- ProjectInspection restituisce neutral ProjectSnapshot; non include AppBuilder/PackagerSigner. ResolvedDependencies separato da BuildPlan/BuildProducts. Backend SwiftPM ufficiale dietro contract resolve/build, senza implementare un motore parallelo.
- ApplicationService possiede l'orchestrazione ora nel main; CLI parsing/rendering soltanto. Obiettivo <300 righe non sostituisce la verifica dell'ownership.
- Packaging consuma artefatti risorsa completati; signing e device operations separati. Nessun servizio dipende da console/UI.
- Header pubblici per modulo, include private e link PRIVATE/PUBLIC motivati. CMake enforcea dipendenze; niente intera src pubblica indiscriminatamente.
- Rimuovere stato globale per environment/configuration della singola build; child environments espliciti e contexts concorrenti. Tests linkano librerie reali e non duplicano implementazioni.
- Operation adapter versionato asincrono: requests, cancellation/deadline, capabilities, stream/replay/snapshot e errori. Named Pipe locale documentata con controllo accesso, framing e limiti; invocazione in-process usa gli stessi servizi.
- Parser libplist come primary backend con fixture OpenStep/XML/binary/JSON e corner cases; eliminare fallback proprietario soltanto dopo copertura, mantenendo unsupported fields. Nessuna promessa 100% universale senza evidence.
- Operazioni project/plist create/edit esplicite e separate dalla build: snapshot/versione file, conflict detection, atomic write e preservazione campi non supportati; template standard upstream-compatible. Nessuna edit automatica per riparare una compilazione.
- Native engine build via CMake/compiler-discovered header dependencies: verificare clean build, unchanged rebuild e modifica header locale; support scripts restano driver senza seconda implementazione di cache/build applicativa.

Gate: identico risultato CLI e client adapter sul medesimo BuildRequest; nessuna implementazione build alternativa; dipendenze vietate rifiutate da build/check architetturali; operazioni simultanee non contaminano setting e credenziali.

### M5.1 Lifecycle SDK, ambiente e credenziali

Le parti già implementate vengono preservate e ricontrollate al confine servizio, senza riscritture speculative. Completare inspect/install/validate/repair/remove di versioni gestite, SDK list/select/import/download/remove con lease attive che impediscono rimozioni pericolose e rollback transazionale. Sessioni/cookie Apple separati da credenziali signing, migrazione DPAPI senza stampa dei segreti. Acquisition con provider autentico: catalogo, scadenza/renewal, transfer/resume solo se supportato, integrity/provenance, extraction e registration atomiche. SDK/toolchain prerelease solo quando richiesti da metadati ufficiali. Un cookie esistente non dimostra autorizzazione al download. Test di failure/interruption/removal in use e percorso originale, senza alterare installazione o credenziali dell'utente per un negative control.

## 10. M6 — Zero WSL, provider nativi originali

### M6.1 Fattibilità e closure, prima del runtime completo

Avanzamento 2026-10-04: estrazione selettiva nativa condivisa con SDK, 33/33 test
PASS; sei server originali estratti dall'archivio autenticato, checksum/firma/catena
validi e hash sorgente invariato. LLVM sui file completi conferma ARM64; server
XcodeDefault: 15 dylib strong, dyld e chained fixups. Evidenza nei documenti
ARCHIVE_TREE_EXTRACTION.md / XIP_RUNTIME_INPUT_INVENTORY.md e checkpoint.
Questo chiude l'estrazione dei server, non la closure transitiva né il gate M6.1.
Successivo avanzamento: inventario nativo completo di slice x86_64/ARM64, input
foreign letti senza bypassare il gate CPU del runtime; 33/33 test PASS (39.02 s).
Albero host originale derivato dal RPATH del server, estratto e verificato:
64 file + un symlink; 35 percorsi Mach-O ARM64 ispezionati, 44 import diretti
distinti. Inventario e sorgenti disponibili non provano closure/ABI/esecuzione.
Anche le cinque varianti Preview dell'archivio originale sono estratte/verificate
ed ispezionate dal servizio nativo: ARM64, host macOS; variante iPhoneOS con
16 import (11 strong / 5 weak), Foundation/runtime ancora da risolvere.
Vedere DARWIN_SLICE_INVENTORY.md; M6.1 resta aperto.
Avanzamento 2026-10-05: resolver nativo di percorsi/dependenze da immagini reali,
RPATH ereditati ancorati al dichiarante, case/CPU e provider originali controllati;
33/33 test PASS. Analisi server + plugin iPhoneOS: 14 immagini, 129 archi, 79
risolti; sei nomi strong mancanti nei mount (Foundation/dyld/libSystem/libc++/
libobjc/swiftCore). Non sono risolte le dipendenze dei provider mancanti né il
runtime/ABI/ISA; nessuna espansione originale PASS. Vedere DARWIN_DEPENDENCY_CLOSURE.md.



Le vecchie viste locali dei plugin includono Mach-O fat x86_64/arm64, non DLL PE nonostante il suffisso .dll; non costituiscono prova delle slice dell’archivio Apple attualmente selezionato, i cui14 file server/plugin trattenuti risultano ARM64-only nel ricontrollo nativo del2026-10-07. L'ispezione di SwiftUIMacros/ObservationMacros/SwiftDataMacros mostra dipendenze SwiftSyntax, Swift runtime, libSystem e, a seconda dei metadati, Objective-C/Foundation/libc++/Dispatch. Questi nomi descrivono evidenza, non devono controllare branch applicativi.

- Inventariare transitive closure dal formato binario e dai manifest autorevoli, inclusi swift-plugin-server/runtime, LC_RPATH e load commands. Distinguere host CPU da architecture iOS del prodotto.
- Disegnare runtime Darwin compatibile Windows: loader/dyld, ABI/chiamate, TLS/threading, filesystem/path, POSIX/IPC/signals richiesti, Objective-C/Swift/unwind/runtime initialization. Nessun successo per syscall/metodo non implementato.
- Preferire esecuzione stessa ISA sulla CPU host; slice selection generica. Supporto CPU non realizzato dichiarato unsupported, senza fingere che il loader sia un emulatore universale.
- Mantenere codice upstream originale; componenti proprietari importati dall'installazione utente autenticata, hash/version/licenze manifestati, senza distribuirli implicitamente.
- Porting/build Windows di componenti upstream disponibili soltanto se sorgenti invariati e build host derivata da metadata ufficiali; non sostituire binari Apple non eseguibili con macro equivalenti scritte da OPENFRUIT.

Gate di fattibilità: host runtime di test esegue server originale e un plugin originale con risultato necessario al consumer, senza alcun avvio WSL. Documentare closure completa e semantiche ancora mancanti. Se il gate fallisce, checkpoint registra la dipendenza tecnica e il progetto resta incompleto; non si ripristina WSL come soluzione finale.

### M6.2 Loader, transport e macro host

Avanzamento del prerequisito runtime: decoder LZBITMAP originale compilato senza
patch su Windows, wrapper nativo con limiti e verifica dei resource fork.
Esperimento sul file dyld cache originale: 753664 byte decompressi; tutti i 46
hash APFS verificano i byte decompressi e coprono il file intero. Questa prova
è ora riprodotta dalla CLI installata con estrazione automatica da percorso,
metadati/stream/extents/dimensione/hash derivati, lease stabile e output in
quarantena. Verifica indipendente di tutti i byte e dei 46 hash PASS.
Non chiude l'esecuzione di un processo Apple originale. Vedere
APFS_NATIVE_COMPRESSION.md e APFS_NATIVE_FILE_EXTRACTION.md; M6 resta aperto.
Parser nativo dyld cache: CLI installata deriva UUID/mapping, 79 subcache e
4088 immagini +4088 text records; tutte le tabelle originali e tutti i percorsi
dei figli verificati indipendentemente. I file dei figli e la closure non sono
ancora verificati. Il LINKEDIT originale da1674805248 byte richiede streaming
APFS oltre il limite512MiB attuale. Vedere DYLD_NATIVE_CACHE_METADATA.md.
Streaming nativo APFS ora integrato nel comando standard: LINKEDIT originale
1674805248 byte estratto senza buffer intero, tutti102222 hash originali e SHA256
completo verificati indipendentemente; picco osservato155271168 byte. Il vecchio
limite512MiB resta solo nell'API esplicita in memoria. Prossimo contratto: contesto
parent derivato per i subcache con regione dichiarata0; nessuna riscrittura degli
header Apple. Vedere APFS_NATIVE_STREAMING.md. Closure/processo originale aperti.

- Loader Mach-O robusto con segment/protection, relocations/rebase/bind/chained fixups richiesti, symbols/rpaths/dylibs, constructors/TLS/unwind, CPU checks e malformed binary rejection; implementare solo contratti verificati e ampliare dal primo errore reale.
- Trasporto plugin conforme alla versione negoziata, JSON parsing reale/escaping, frame limits, capabilities effettive, diagnostiche/cancellation e crash propagation. Non LoadLibraryW per un Mach-O.
- Provider scelto da formato/metadati/capabilities/host, mai dai nomi. Identità server/toolchain/plugin coerenti e registrate. Scheduler N=2 per operation/runtime boundary, senza pool duplicati che bypassano il limite.
- Plugin mancante/incompatibile/provider failed restituiscono errore; nessuna espansione placeholder. Empty expansion accettata solo quando realmente restituita dal plugin eseguito.
- Test generici OPENFRUIT-owned per protocollo; consumer upstream necessario per prova originale. Confronti legacy eventualmente isolati non contano come PASS del nuovo provider.

### M6.3 Tutti gli altri percorsi WSL

- SwiftShims/import fallback: correggere contratti nativi Windows/filesystem/module cache/toolchain; nessuna compilazione Linux di fallback nel candidato finale.
- Shell phases: backend POSIX su Windows con /bin/sh, environment e tool/path semantics generiche; rispettare script upstream e phase input/output ordering. Dichiarare esplicitamente unsupported commands/host tools fino alla loro implementazione. Un layer Unix nativo non implica WSL; non riscrivere script per app.
- Asset SVG: rasterizer nativo Windows importato/buildato/verificato con checksum; rimuovere fallback wsl.exe dal compiler asset. Verificare tutti i formati asset effettivamente richiesti; warning/skip non deve nascondere risorse obbligatorie mancanti.
- Bootstrap/inspect/capabilities/download/install: eliminare probing e dipendenze Linux, non soltanto i fallback durante compile.
- Build/package release della configurazione finale non linkano/distribuiscono il bridge WSL. Materiale legacy può restare in storia o harness isolati senza reachable production path.

Gate zero WSL: eseguire operazioni supportate e reference build su Windows pulito senza WSL installato, con inventario completo dei processi diretti/indiretti. Nessun wsl.exe/Linux process/VHDX richiesto o creato. Non disinstallare WSL dalla macchina dell'utente per effettuare il test.

## 11. M7 — Risorse e dispositivi

- Conservare OpenIB in-process e indipendente. Propagare Diagnostics originali (code/severity/file/line/node reference quando disponibile) nel sink, senza flatten a messaggi concatenati. Fixture storyboard/XIB/nib e bundle verificati; confronti funzionali con output atteso, non solo esistenza file.
- Risorse asset/CoreData/intents/localizzazione: task/input/output/tools/settings autorevoli; generazioni outside upstream, packaging consuma prodotti completati. No fallback silenzioso a file non compilati/asset omessi.
- Device backend nativo con librerie/protocol contracts supportati: enumerate/pairing/install/launch/logs secondo capability. Rimuovere Python/tool subprocess dalla dipendenza standard dopo equivalent original-path evidence; assenza capability deve essere esplicita.
- Named Pipe device service solo se serve session ownership/longevity; preferire riuso dell'operation adapter rispetto a demoni duplicati. Cancellation, accesso locale, reconnect e device-loss verificati.
- Install/launch su device è milestone separata dal gate IPA corrente; niente dichiarazione debugger implementato per la sola presenza di log.

Gate: risorse finali coerenti, errori navigabili, device fixture negative e hardware originale quando disponibile. Se mancano device/credenziali, segnare le prove non eseguite, non PASS.

## 12. M8 — Performance, release e accettazione

### Performance e robustezza misurate

- Prima correttezza, poi ottimizzare discovery, dedup/storage e process overhead con trace durata/I/O/RAM e workload congelato.
- Per discovery utilizzare API batch Win32 solo quando benchmark mostra vantaggio preservando completezza/ambiguity handling. Cache invalidation e bounded scans prima di micro-ottimizzazioni.
- Archivi: confrontare streaming già presente e mmap; implementare mmap solo dove limita effettivamente memoria/I/O, con limiti, cancellation e file replacement checks. Le primitive non sono milestone se non arrivano al consumer reale.
- Budget memoria su risorse disponibili e task cost, coordinato dallo scheduler; jobs espliciti con policy documentata. Nessuna garanzia universale anti-OOM basata solo su RAM totale/2.
- Estendere atomic publication agli artefatti condivisi; prova lock antivirus/transient sharing e crash-safe recovery. Hard-link immutable vs mutable testato.
- Misure cold/warm separate per download, package, target, resource e module caches; hash candidate/inputs/output e telemetry overhead. Non promettere accelerazione 14x generalizzata da un run.

### Distribuzione

- Package installabile da artefatti CMake install, include runtime/host/tool adapter necessari e simboli matching. Non zip manuale contenente solo openfruit/openib.
- Manifest versione/checksum/licenze, separazione componenti Apple user-provided, toolchain/SDK selection autenticata e integrity-verified, repair/uninstall scoped ai managed roots.
- Clean Windows installation smoke: bootstrap/capabilities/inspect/build/package/sign senza repository sorgente e senza WSL. CLI standard e launcher forwarder devono usare lo stesso layout.
- Tag soltanto sul commit validato; record release con hash, provenance e prove reali. Push/publish restano operazioni esplicite separate: non eseguite dal presente piano.

### Accettazione finale

1. Tutti i difetti dell'audit hanno prova del contract e, dove pertinente, original-path PASS. Test che preiniettano valori da derivare non contano.
2. Nextcloud: tracked upstream e status completamente puliti prima del gate, dimensioni congelate/registrate, formerly failing targets ricostruiti, IPA verificato indipendentemente per tutti i bundle.
3. SDK adeguato autentico e profili compatibili realmente disponibili; nessuna invenzione API, App Group fallback, espansione fake o missing-symbol workaround globale.
4. Macro/plugin originali eseguiti nel provider nativo, concurrency N=2, identità e risultati registrati.
5. Reference matrix CampUS/IceCubesApp/Swiftfin/Nextcloud: stage risultato e limitazioni esplicite; nessun caso speciale di produzione.
6. Release-grade clean/versioned caches per la validazione finale, senza eliminare installazione/credenziali né bypassare il contratto cache.
7. JSON-only machine stream valido, journaling/progress/cancel corretti; CLI e adapter usano medesime librerie.
8. Zero WSL provato con sistema privo di WSL e process inventory; includere shell phases/SVG/SwiftShims e bootstrap.
9. Package release riproducibile e verificato; checkpoint/documentazione descrivono solo risultati realmente ottenuti.

## 13. Disciplina di esecuzione

Misurazione M6 integrata il 2026-10-09: `runtime report-progress` riusa inventario
statico, probe originale, identità del candidato e ledger dei contratti; confronta
checkpoint e prove per ambito/componente. Distinguere implementato, parziale,
mancante, da revisionare e livello di verifica; dispatch e import non provano
semantica completa. Totale dei requisiti sconosciuto: nessuna percentuale globale.
Aggiornare le metriche ad ogni requisito/prova nuovo, senza sostituire i gate reali.
Vedere `DARWIN_RUNTIME_PROGRESS.md`, `DARWIN_CONTRACT_LEDGER.json` e il checkpoint
corrente per il primo errore causale e le evidenze effettivamente validate.

- Un gruppo coerente di contratti, un candidato congelato. Il workflow nativo multi-agent per sottosistemi è definito in `DARWIN_MULTI_AGENT.md`: ownership indipendente, Main unico integratore dei file condivisi, prove per ogni ambito assegnato. Ogni candidato: native rebuild, SHA-256, test utili, percorso reale originario, commit focalizzato, checkpoint aggiornato al cambio causale. I gruppi sono pianificati anche da inventario/reachability e sorgenti, non soltanto dal prossimo crash.
- Reuse warm artifacts validi e indipendenti durante sviluppo; invalidare soltanto closure coinvolta. Clean-cache finale quando cache-sensitive o release-grade.
- Nessun mega-refactor insieme a SDK/toolchain migration o signing changes. Gli spike di fattibilità non diventano workaround runtime.
- Fermarsi al primo nuovo errore causale, alle autorizzazioni esterne mancanti o a una semantica nativa non implementata. Documentare il minimo esperimento successivo; non dichiarare PASS aggirando il contratto.
- Nessuna durata totale promessa: M6 è un progetto di runtime/ABI con rischio tecnico maggiore delle correzioni locali. Le stime vengono prodotte dopo closure e gate M6.1, con misure e scope verificati.

Prima unità operativa: M0 e inventario M6.1, poi M1.1 per ottenere diagnostica affidabile. Il presente documento registra anche l'avanzamento verificato sopra; non attesta deploy, pubblicazione o completamento dell'architettura.
