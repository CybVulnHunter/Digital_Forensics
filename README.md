# Awesome Forensics [![Link Status](https://github.com/cugu/awesome-forensics/workflows/CI/badge.svg)](https://github.com/cugu/awesome-forensics)

Curated list of awesome **free** (mostly open source) forensic analysis tools and resources.

- Awesome Forensics
  - [Collections](#collections)
  - [Tools](#tools)
    - [Distributions](#distributions)
    - [Frameworks](#frameworks)
    - [Live Forensics](#live-forensics)
    - [IOC Scanner](#ioc-scanner)
    - [Acquisition](#acquisition)
    - [Imaging](#imaging)
    - [Carving](#carving)
    - [Memory Forensics](#memory-forensics)
    - [Network Forensics](#network-forensics)
    - [Windows Artifacts](#windows-artifacts)
      - [NTFS/MFT Processing](#ntfsmft-processing)
    - [OS X Forensics](#os-x-forensics)
    - [Mobile Forensics](#mobile-forensics)
    - [Docker Forensics](#docker-forensics)
    - [Internet Artifacts](#internet-artifacts)
    - [Timeline Analysis](#timeline-analysis)
    - [Disk image handling](#disk-image-handling)
    - [Decryption](#decryption)
    - [Management](#management)
    - [Picture Analysis](#picture-analysis)
    - [Metadata Forensics](#metadata-forensics)
    - [Steganography](#steganography)
  - [Learn Forensics](#learn-forensics)
    - [CTFs and Challenges](#ctfs-and-challenges)
  - [Resources](#resources)
    - [Web](#web)
    - [Blogs](#blogs)
    - [Books](#books)
    - [File System Corpora](#file-system-corpora)
    - [Other](#other)
    - [Labs](#labs)
  - [Related Awesome Lists](#related-awesome-lists)
  - [Contributing](#contributing)

---
## Collections

- [AboutDFIR – The Definitive Compendium Project](https://aboutdfir.com) - Collection of forensic resources for learning and research. Offers lists of certifications, books, blogs, challenges and more
- :star: [ForensicArtifacts.com Artifact Repository](https://github.com/ForensicArtifacts/artifacts) - Machine-readable knowledge base of forensic artifacts

## Tools

- [Forensics tools on Wikipedia](https://en.wikipedia.org/wiki/List_of_digital_forensics_tools)
- [Eric Zimmerman's Tools](https://ericzimmerman.github.io/#!index.md)

### Distributions

- [bitscout](https://github.com/vitaly-kamluk/bitscout) - LiveCD/LiveUSB for remote forensic acquisition and analysis
- [Remnux](https://remnux.org/) - Distro for reverse-engineering and analyzing malicious software
- [SANS Investigative Forensics Toolkit (sift)](https://github.com/teamdfir/sift) - Linux distribution for forensic analysis
- [Tsurugi Linux](https://tsurugi-linux.org/) - Linux distribution for forensic analysis
- [WinFE](https://www.winfe.net/home) - Windows Forensics enviroment

### Frameworks

- :star:[Autopsy](http://www.sleuthkit.org/autopsy/) - SleuthKit GUI
- [dexter](https://github.com/coinbase/dexter) - Dexter is a forensics acquisition framework designed to be extensible and secure
- [dff](https://github.com/arxsys/dff) - Forensic framework
- [Dissect](https://github.com/fox-it/dissect) - Dissect is a digital forensics & incident response framework and toolset that allows you to quickly access and analyse forensic artefacts from various disk and file formats, developed by Fox-IT (part of NCC Group).
- [hashlookup-forensic-analyser](https://github.com/hashlookup/hashlookup-forensic-analyser) - A tool to analyse files from a forensic acquisition to find known/unknown hashes from [hashlookup](https://www.circl.lu/services/hashlookup/) API or using a local Bloom filter.
- [IntelMQ](https://github.com/certtools/intelmq) - IntelMQ collects and processes security feeds
- [Kuiper](https://github.com/DFIRKuiper/Kuiper) - Digital Investigation Platform
- [Laika BOSS](https://github.com/lmco/laikaboss) - Laika is an object scanner and intrusion detection system
- [OpenRelik](https://openrelik.org/) - Forensic platform to store file artifacts and run workflows
- [PowerForensics](https://github.com/Invoke-IR/PowerForensics) - PowerForensics is a framework for live disk forensic analysis
- [TAPIR](https://github.com/tap-ir/tapir) - TAPIR (Trustable Artifacts Parser for Incident Response) is a multi-user, client/server, incident response framework
- :star: [The Sleuth Kit](https://github.com/sleuthkit/sleuthkit) - Tools for low level forensic analysis
- [turbinia](https://github.com/google/turbinia) - Turbinia is an open-source framework for deploying, managing, and running forensic workloads on cloud platforms
- [IPED - Indexador e Processador de Evidências Digitais](https://github.com/sepinf-inc/IPED) - Brazilian Federal Police Tool for Forensic Investigations
- [Wombat Forensics](https://github.com/pjrinaldi/wombatforensics) - Forensic GUI tool

### Live Forensics

- [grr](https://github.com/google/grr) - GRR Rapid Response: remote live forensics for incident response
- [Linux Expl0rer](https://github.com/intezer/linux-explorer) - Easy-to-use live forensics toolbox for Linux endpoints written in Python & Flask
- [mig](https://github.com/mozilla/mig) - Distributed & real time digital forensics at the speed of the cloud
- [osquery](https://github.com/osquery/osquery) - SQL powered operating system analytics
- [POFR](https://github.com/gmagklaras/pofr) - The Penguin OS Flight Recorder collects, stores and organizes for further analysis process execution, file access and network/socket endpoint data from the Linux Operating System.
- [UAC](https://github.com/tclahr/uac) - UAC (Unix-like Artifacts Collector) is a Live Response collection script for Incident Response that makes use of native binaries and tools to automate the collection of AIX, Android, ESXi, FreeBSD, Linux, macOS, NetBSD, NetScaler, OpenBSD and Solaris systems artifacts.

### IOC Scanner

- [Fastfinder](https://github.com/codeyourweb/fastfinder) - Fast customisable cross-platform suspicious file finder. Supports md5/sha1/sha256 hashes, literal/wildcard strings, regular expressions and YARA rules
- [Fenrir](https://github.com/Neo23x0/Fenrir) - Simple Bash IOC Scanner
- [Loki](https://github.com/Neo23x0/Loki) - Simple IOC and Incident Response Scanner
- [Redline](https://fireeye.market/apps/211364) - Free endpoint security tool from FireEye
- [THOR Lite](https://www.nextron-systems.com/thor-lite/) - Free IOC and YARA Scanner
- [recon](https://github.com/rusty-ferris-club/recon) - Performance oriented file finder with support for SQL querying, index and analyze file metadata with support for YARA.

### Acquisition

- [Acquire](https://github.com/fox-it/acquire) - Acquire is a tool to quickly gather forensic artifacts from disk images or a live system into a lightweight container
- [artifactcollector](https://github.com/forensicanalysis/artifactcollector) - A customizable agent to collect forensic artifacts on any Windows, macOS or Linux system
- [ArtifactExtractor](https://github.com/Silv3rHorn/ArtifactExtractor) - Extract common Windows artifacts from source images and VSCs
- [AVML](https://github.com/microsoft/avml) - A portable volatile memory acquisition tool for Linux
- [Belkasoft RAM Capturer](https://belkasoft.com/ram-capturer) - Volatile Memory Acquisition Tool
- [DFIR ORC](https://dfir-orc.github.io/) - Forensics artefact collection tool for systems running Microsoft Windows
- [FastIR Collector](https://github.com/SekoiaLab/Fastir_Collector) - Collect artifacts on windows
- [FireEye Memoryze](https://fireeye.market/apps/211368) - A free memory forensic software
- [FIT](https://github.com/fit-project/fit) - Forensic acquisition of web pages, emails, social media, etc.
- [ForensicMiner](https://github.com/securityjoes/ForensicMiner) - A PowerShell-based DFIR automation tool, for artifact and evidence collection on Windows machines.
- [Fuji](https://github.com/Lazza/Fuji/) - MacOS forensic acquisition made simple. It creates full file system copies or targeted collection of Mac computers.
- [LiME](https://github.com/504ensicsLabs/LiME) - Loadable Kernel Module (LKM), which allows the acquisition of volatile memory from Linux and Linux-based devices, formerly called DMD
- [Magnet RAM Capture / DumpIt](https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/) - A free imaging tool designed to capture the physical memory
- [SPECTR3](https://github.com/alpine-sec/SPECTR3) - Acquire, triage and investigate remote evidence via portable iSCSI readonly access
- [UFADE](https://github.com/prosch88/UFADE) - Extract files from iOS devices on Linux and MacOS. Mostly a wrapper for pymobiledevice3. Creates iTunes-style backups and advanced logical backups.
- [unix_collector](https://github.com/op7ic/unix_collector) - A live forensic collection script for UNIX-like systems as a single script.
- [Velociraptor](https://github.com/Velocidex/velociraptor) - Velociraptor is a tool for collecting host based state information using Velocidex Query Language (VQL) queries
- [WinTriage](https://www.securizame.com/wintriage-the-triage-tool-for-windows-dfirers/) - Wintriage is a live response tool that extracts Windows artifacts. It must be executed with local or domain administrator privileges and recommended to be done from an external drive.

### Imaging

- [dc3dd](https://sourceforge.net/projects/dc3dd/) - Improved version of dd
- [dcfldd](https://sourceforge.net/projects/dcfldd/) - Different improved version of dd (this version has some bugs!, another version is on github [adulau/dcfldd](https://github.com/adulau/dcfldd))
- [FTK Imager](https://www.exterro.com/digital-forensics-software/ftk-imager) - Free imageing tool for windows
- :star: [Guymager](https://sourceforge.net/projects/guymager/) - Open source version for disk imageing on linux systems
- [4n6pi](https://github.com/plonxyz/4n6pi) - Forensic disk imager, designed to run on a Raspberry Pi, powered by libewf

### Carving

- [bstrings](https://github.com/EricZimmerman/bstrings) - Improved strings utility
- [bulk_extractor](https://github.com/simsong/bulk_extractor) - Extracts information such as email addresses, creditcard numbers and histrograms from disk images
- [floss](https://github.com/mandiant/flare-floss) - Static analysis tool to automatically deobfuscate strings from malware binaries
- :star: [photorec](https://www.cgsecurity.org/wiki/PhotoRec) - File carving tool
- [swap_digger](https://github.com/sevagas/swap_digger) - A bash script used to automate Linux swap analysis, automating swap extraction and searches for Linux user credentials, Web form credentials, Web form emails, etc.

### Memory Forensics

- [inVtero.net](https://github.com/ShaneK2/inVtero.net) - High speed memory analysis framework
  developed in .NET supports all Windows x64, includes code integrity and write support
- [KeeFarce](https://github.com/denandz/KeeFarce) - Extract KeePass passwords from memory
- [MemProcFS](https://github.com/ufrisk/MemProcFS) - An easy and convenient way of accessing physical memory as files a virtual file system.
- [Rekall](https://github.com/google/rekall) - Memory Forensic Framework
- [volatility](https://github.com/volatilityfoundation/volatility) - The memory forensic framework
- [VolUtility](https://github.com/kevthehermit/VolUtility) - Web App for Volatility framework

### Network Forensics

- [Kismet](https://github.com/kismetwireless/kismet) - A passive wireless sniffer
- [NetworkMiner](https://www.netresec.com/?page=Networkminer) - Network Forensic Analysis Tool
- [Squey](https://squey.org) - Logs/PCAP visualization software designed to detect anomalies and weak signals in large amounts of data.
- :star: [WireShark](https://www.wireshark.org/) - A network protocol analyzer

### Windows Artifacts

- [Beagle](https://github.com/yampelo/beagle) -  Transform data sources and logs into graphs
- [Blauhaunt](https://github.com/cgosec/Blauhaunt) - A tool collection for filtering and visualizing logon events
- [FRED](https://www.pinguin.lu/fred) - Cross-platform microsoft registry hive editor
- [Hayabusa](https://github.com/Yamato-Security/hayabusa) - A a sigma-based threat hunting and fast forensics timeline generator for Windows event logs.
- [LastActivityView](https://www.nirsoft.net/utils/computer_activity_view.html) - LastActivityView by Nirsoftis a tool for Windows operating system that collects information from various sources on a running system, and displays a log of actions made by the user and events occurred on this computer. 
- [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - Investigate malicious Windows logon by visualizing and analyzing Windows event log
- [PyShadow](https://github.com/alicangnll/pyshadow) - A library for Windows to read shadow copies, delete shadow copies, create symbolic links to shadow copies, and create shadow copies
- [python-evt](https://github.com/williballenthin/python-evt) - Pure Python parser for classic Windows Event Log files (.evt)
- [RegRipper3.0](https://github.com/keydet89/RegRipper3.0) - RegRipper is an open source Perl tool for parsing the Registry and presenting it for analysis
- [RegRippy](https://github.com/airbus-cert/regrippy) - A framework for reading and extracting useful forensics data from Windows registry hives

#### NTFS/MFT Processing

- [MFT-Parsers](http://az4n6.blogspot.com/2015/09/whos-your-master-mft-parsers-reviewed.html) - Comparison of MFT-Parsers
- [MFTEcmd](https://binaryforay.blogspot.com/2018/06/introducing-mftecmd.html) - MFT Parser by Eric Zimmerman
- [MFTExtractor](https://github.com/aarsakian/MFTExtractor) - MFT-Parser
- [MFTMactime](https://github.com/kero99/mftmactime) - MFT and USN parser that allows direct extraction in filesystem timeline format (mactime), dump all resident files in the MFT in their original folder structure and run yara rules over them all.
- [NTFS journal parser](http://strozfriedberg.github.io/ntfs-linker/)
- [NTFS USN Journal parser](https://github.com/PoorBillionaire/USN-Journal-Parser)
- [RecuperaBit](https://github.com/Lazza/RecuperaBit) - Reconstruct and recover NTFS data
- [python-ntfs](https://github.com/williballenthin/python-ntfs) - NTFS analysis

### OS X Forensics

- [APFS Fuse](https://github.com/sgan81/apfs-fuse) - A read-only FUSE driver for the new Apple File System
- [mac_apt (macOS Artifact Parsing Tool)](https://github.com/ydkhatri/mac_apt) - Extracts forensic artifacts from disk images or live machines
- [MacLocationsScraper](https://github.com/mac4n6/Mac-Locations-Scraper) - Dump the contents of the location database files on iOS and macOS
- [macMRUParser](https://github.com/mac4n6/macMRU-Parser) - Python script to parse the Most Recently Used (MRU) plist files on macOS into a more human friendly format
- [OSXAuditor](https://github.com/jipegit/OSXAuditor)
- [OSX Collect](https://github.com/Yelp/osxcollector)

### Mobile Forensics

- [Andriller](https://github.com/den4uk/andriller) - A software utility with a collection of forensic tools for smartphones
- [ALEAPP](https://github.com/abrignoni/ALEAPP) - An Android Logs Events and Protobuf Parser
- [ArtEx](https://www.doubleblak.com/index.php) - Artifact Examiner for iOS Full File System extractions
- [iLEAPP](https://github.com/abrignoni/iLEAPP) - An iOS Logs, Events, And Plists Parser
- [iOS Frequent Locations Dumper](https://github.com/mac4n6/iOS-Frequent-Locations-Dumper) - Dump the contents of the StateModel#.archive files located in /private/var/mobile/Library/Caches/com.apple.routined/
- [MEAT](https://github.com/jfarley248/MEAT) - Perform different kinds of acquisitions on iOS devices
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) - An automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis.
- [OpenBackupExtractor](https://github.com/vgmoose/OpenBackupExtractor) - An app for extracting data from iPhone and iPad backups.


### Docker Forensics

- [dof (Docker Forensics Toolkit)](https://github.com/docker-forensics-toolkit/toolkit) - Extracts and interprets forensic artifacts from disk images of Docker Host systems
- [Docker Explorer](https://github.com/google/docker-explorer) Extracts and interprets forensic artifacts from disk images of Docker Host systems

### Internet Artifacts

- [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) - A small utility that reads the cache folder of Google Chrome Web browser, and displays the list of all files currently stored in the cache
- [chrome-url-dumper](https://github.com/eLoopWoo/chrome-url-dumper) - Dump all local stored infromation collected by Chrome
- [hindsight](https://github.com/obsidianforensics/hindsight) - Internet history forensics for Google Chrome/Chromium
- [IE10Analyzer](https://github.com/moaistory/IE10Analyzer) - This tool can parse normal records and recover deleted records in WebCacheV01.dat.
- [unfurl](https://github.com/obsidianforensics/unfurl) - Extract and visualize data from URLs
- [WinSearchDBAnalyzer](https://github.com/moaistory/WinSearchDBAnalyzer) - This tool can parse normal records and recover deleted records in Windows.edb.

### Timeline Analysis

- [DFTimewolf](https://github.com/log2timeline/dftimewolf) - Framework for orchestrating forensic collection, processing and data export using GRR and Rekall
- :star: [plaso](https://github.com/log2timeline/plaso) - Extract timestamps from various files and aggregate them
- [Timeline Explorer](https://binaryforay.blogspot.com/2017/04/introducing-timeline-explorer-v0400.html) - Timeline Analysis tool for CSV and Excel files. Built for SANS FOR508 students
- [timeliner](https://github.com/airbus-cert/timeliner) - A rewrite of mactime, a bodyfile reader
- [timesketch](https://github.com/google/timesketch) - Collaborative forensic timeline analysis

### Disk image handling

- [Disk Arbitrator](https://github.com/aburgh/Disk-Arbitrator) - A Mac OS X forensic utility designed to help the user ensure correct forensic procedures are followed during imaging of a disk device
- [imagemounter](https://github.com/ralphje/imagemounter) - Command line utility and Python package to ease the (un)mounting of forensic disk images
- [libewf](https://github.com/libyal/libewf) - Libewf is a library and some tools to access the Expert Witness Compression Format (EWF, E01)
- [PancakeViewer](https://github.com/forensicmatt/PancakeViewer) - Disk image viewer based in dfvfs, similar to the FTK Imager viewer
- [xmount](https://www.pinguin.lu/xmount) - Convert between different disk image formats

### Decryption

- [hashcat](https://hashcat.net/hashcat/) - Fast password cracker with GPU support
- [John the Ripper](https://www.openwall.com/john/) - Password cracker

### Management

- [Catalyst](https://github.com/SecurityBrewery/catalyst) - Catalyst is an open source security automation and ticket system
- [dfirtrack](https://github.com/dfirtrack/dfirtrack) - Digital Forensics and Incident Response Tracking application, track systems
- [Incidents](https://github.com/veeral-patel/incidents) - Web application for organizing non-trivial security investigations. Built on the idea that incidents are trees of tickets, where some tickets are leads
- [iris](https://github.com/dfir-iris/iris-web) - Collaborative Incident Response platform

### Picture Analysis

- [Ghiro](https://github.com/Ghirensics/ghiro) - A fully automated tool designed to run forensics analysis over a massive amount of images
- [sherloq](https://github.com/GuidoBartoli/sherloq) - An open-source digital photographic image forensic toolset

### Metadata Forensics

- [ExifTool](https://exiftool.org/) by Phil Harvey
- [FOCA](https://github.com/ElevenPaths/FOCA) - FOCA is a tool used mainly to find metadata and hidden information in the documents

### Steganography

- [Sonicvisualizer](https://www.sonicvisualiser.org)
- [Steghide](https://github.com/StegHigh/steghide) - is a steganography program that hides data in various kinds of image and audio files
- [Wavsteg](https://github.com/samolds/wavsteg) - is a steganography program that hides data in various kinds of image and audio files
- [Zsteg](https://github.com/zed-0xff/zsteg) - A steganographic coder for WAV files

# Tools List

### Satellite and mapping services

-   Bing Maps, satellite and mapping service, has more recent and
    sharper imagery than Google in several areas such as Iraq,
    [bing.com/maps](https://www.bing.com/maps/)
-   Date of the Bing imagery? Check:
    [mvexel.dev.openstreetmap.org/bing](http://mvexel.dev.openstreetmap.org/bing/) 
-   conversion of coordinates, convert geographic coordinates between
    different notation styles,
    [synnatschke.de/geo-tools/coordinate-converter.php](http://www.synnatschke.de/geo-tools/coordinate-converter.php) 
-   DigitalGlobe, paid satellite imagery, but preview available for free
    via the catalogus,
    [browse.digitalglobe.com/imagefinder](https://browse.digitalglobe.com/imagefinder/main.jsp;jsessionid%3D211D96095DB2313696B02534E7F62D64?) 
-   Geograph, georeferenced
    images, [geograph.org](http://www.geograph.org) 
-   GeoNames, an online database of (various spellings of) locations
    names,
    [geonames.org](http://www.geonames.org)
-   Google Earth Pro,
    [google.com/earth/download/gep/agree.html](https://www.google.com/earth/download/gep/agree.html) 
-   Bing Maps satellite imagery layer:
    [ge-map-overlays.appspot.com/bing-maps/aerial](http://ge-map-overlays.appspot.com/bing-maps/aerial) 
-   Google Maps,
    [maps.google.com](http://maps.google.com) 
-   HERE WeGo, mapping service which includes more recent satellite
    imagery from e.g. Iraq,
    [wego.here.com](https://wego.here.com) 
-   Mapillary, crowdsourced street-level photos,
    [mapillary.com](https://www.mapillary.com)
-   OpenStreetCam,[ ](https://www.mapillary.com)crowdsourced
    street-level
    photos, [openstreetcam.org](https://www.openstreetcam.org) 
-   OpenStreetMap,
    [openstreetmap.org](http://www.openstreetmap.org/) 
-   Panoramio,
    [panoramio.com](http://www.panoramio.com) (no
    longer available)
-   Sentinel Playground,
    [apps.sentinel-hub.com/sentinel-playground](http://apps.sentinel-hub.com/sentinel-playground)      
-   TerraServer, also a commercial company selling satellite imagery,
    but previews available:
    [terraserver.com](http://www.terraserver.com)
-   Wikimapia, crowdsourced information related to geographic locations,
    works like Google Maps but possibility to switch between Google,
    Bing, OSM, etc.,
    [wikimapia.org](http://www.wikimapia.org)
-   Yandex Maps,
    [yandex.ru](http://www.yandex.ru) 


# Geobased searches
-   (\$) Echosec, [echosec.net](http://www.echosec.net) (Instagram,
    Twitter, VK, Foursquare)
-   LiveUAmap, aggregated open source information,
    [liveuamap.com](http://www.liveuamap.com) 
-   Afghanistan:
    [afghanistan.liveuamap.com](https://afghanistan.liveuamap.com) 
-   Islamic State:
    [isis.liveuamap.com](http://isis.liveuamap.com) 
-   Syria:
    [syria.liveuamap.com](http://syria.liveuamap.com) 
-   Ukraine:
    [ukraine.liveuamap.com](http://ukraine.liveuamap.com) 
-   Venezuela: venezuela.liveuamap.com
-   (\$) WarWire,
    [warwire.net](http://www.warwire.net) (Twitter,
    Instagram, VK, YouTube)
-   Yomapic,
    [yomapic.com](http://www.yomapic.com)
# Geobased search on:

-   YouTube [youtube.github.io/geo-search-tool/search.html](http://youtube.github.io/geo-search-tool/search.html)
-   Twitter insert this is search box:
    geocode:[coordinates],[radius-km], for example:
    geocode:36.222285,43.998233,2km (only works with km, so 500m =
    0.5km)

# Documents metadata
- Hachoir3 [https://github.com/haypo/hachoir3] (https://github.com/haypo/hachoir3). Python library for metadata extraction from binary streams including MS Office documents
- Forensic wiki [list of metadata extractors](http://www.forensicswiki.org/wiki/Document_Metadata_Extraction)
- Metadata extractor [github](https://github.com/drewnoakes/metadata-extractor)

# Images, videos and metadata
# Image and videos tools
-   Amnesty YouTube Dataviewer, Reverse image (still of video) search
    and exact uploading time,
    [amnestyusa.org/sites/default/custom-scripts/citizenevidence](http://www.amnestyusa.org/sites/default/custom-scripts/citizenevidence/)
-   reverse image search
-   Google Reverse Image Search,
    [images.google.com](http://images.google.com) (also
    available as Chrome and Firefox add-on)
-   TinEye,
    [tineye.com](http://www.tineye.com) 
-   Yandex, be aware that sometimes Russia’s Yandex has better results
    ([example](https://twitter.com/trbrtc/status/900708029389307904)
    than Google’s reverse image search,
    [yandex.com/images](https://yandex.com/images/) 

# Photo/video metadata (EXIF and e.t.c.)
-   Jeffrey's Image Metadata Viewer, to view the metadata of (online)
    photos,
    [exif.regex.info/exif.cgi](http://exif.regex.info/exif.cgi) 
-   Irfanview,
    [irfanview.com](https://irfanview.com)
-   Foca. Metadata extraction tool [elevenpaths.com](https://www.elevenpaths.com/labstools/foca/index.html)
- [Goofile](https://tools.kali.org/information-gathering/goofile). Download and extract metadata
- Splunk and Metadata automation. [Splunk](https://blog.sweepatic.com/metadata-hackers-best-friend/)
-   Foto
    Forensics,[fotoforensics.com](http://fotoforensics.com)        
-   Image Forensics,
    [https://29a.ch/photo-forensics/\#level-sweep](https://29a.ch/photo-forensics/%23level-sweep)
-   InVID, verification plugin to help journalists verify images and
    videos and debunk fake news,
    [invid-project.eu]http://www.invid-project.eu/invid-releases-fake-video-news-debunker-firefox-provides-code-open-source-mit-licence/) (plugins
    for
    [Chrome](https://goo.gl/Fo8i73) and
    Firefox
    ([Windows](http://www.invid-project.eu/wp-content/uploads/2017/07/fake_video_news_debunker_by_invid-0.55-anfx-windows.zip),
    [Mac OS
    X](http://www.invid-project.eu/wp-content/uploads/2017/07/InVID-verification-ext-v0.54fx-mac.zip),
    [Linux](http://www.invid-project.eu/wp-content/uploads/2017/07/InVID-verification-ext-v0.54fx-linux.zip).

# Social media

# Multiple social networks
-   NacheChk. Same name check over dozens of social networks [namechk.com](https://namechk.com/)

# Facebook
-   Facebook Scanner, automatically advanced searched for Facebook
    profiles, [stalkscan.com](http://stalkscan.com/)
-   Facebook Search Tool, find accounts by name, email, screen name and
    phone,
    [netbootcamp.org/facebook.html](http://netbootcamp.org/facebook.html) 
-   Lookup-ID, another very complete Facebook search tool,
    [lookup-id.com](http://lookup-id.com/)
-   Facebook Graph tips, automatically advanced searches for Facebook
    profiles,
    [graph.tips](http://graph.tips/beta) 
-   Facebook Livemap, live broadcasts around the world, mapped on the
    world,
    [facebook.com/livemap](https://www.facebook.com/livemap/) 
-   Facebook Video Downloader Online, for downloading Facebook videos,
    [fbdown.net](http://www.fbdown.net/)
-   Facebook search tool, advanced search tool for Facebook profiles,
    [http://inteltechniques.com/osint/menu.facebook.html](http://inteltechniques.com/osint/menu.facebook.html) 
-   peoplefindThor, advanced search tool for Facebook profiles,
    [peoplefindthor.dk](https://peoplefindthor.dk)

# LinkedIn

-   Socilab, allows users to visualise and analyse your own LinkedIn
    network,
    [socilab.com](http://socilab.com/%23home) 

# Snapchat
-   Snap Map, a searchable map of geotagged snaps, via the mobile
    application, read
    [here](https://techcrunch.com/2017/06/21/snap-map/) how.

# Tumblr

-   Tumblr Originals, find posts uploaded by the account, thus excluding
    reblogs,
    [studiomoh.com/fun/tumblr\_originals](http://www.studiomoh.com/fun/tumblr_originals) 

# Twitter

-   advanced search,
    [twitter.com/search-advanced](https://twitter.com/search-advanced)
-   [C](https://twitter.com/search-advanced),
    [tweetbeaver.com/index.php](https://tweetbeaver.com/index.php)
# Geobased searches

-   On Twitter, insert this is search box:
    geocode:[coordinates],[radius-km], for example:
    geocode:36.222285,43.998233,2km
-   Onemilliontweetmap, maps tweets per location up to 6hrs old, and has
    a keyword search option,
    [onemilliontweetmap.com](http://onemilliontweetmap.com/) 

-   Union Metrics, find the reach of tweets,
    [tweetreach.com/](https://tweetreach.com/) 

# Advanced Search Operators:

-   term1 term2 - tweets with both term1 and term2 in any order (e.g.
    twitter metrics)
-   term1 OR term2 - tweets with either term1 or term2 (e.g. analytics
    OR metrics)
-   “term1 term2” - tweets with the phrase “term1 term2” (e.g. "twitter
    metrics")
-   term1 -term2 - tweets with term1 but not term2 (e.g. twitter
    -facebook)
-   @username - tweets mentioning or RTing a specific user (e.g.
    @unionmetrics)
-   from:username - tweets from a specific Twitter user (e.g.
    from:unionmetrics)
-   since:YYYY-MM-DD - tweets after a specific date in UTC (e.g.
    since:2017-03-30)
-   until:YYYY-MM-DD - tweets before a specific date in UTC (e.g.
    until:2017-03-30)

# YouTube
-   Amnesty YouTube Dataviewer, Reverse image (still of video) search
    and exact uploading time,
    [amnestyusa.org/sites/default/custom-scripts/citizenevidence](http://www.amnestyusa.org/sites/default/custom-scripts/citizenevidence/)

# Transport
# Aircraft

-   OpenSky. Free aircraft tracking project [opensky-network.org](https://opensky-network.org/)
-   ADS-B Exchange Global Radar, which also includes a number of
    [military
    aircraft](https://www.adsbexchange.com/airborne-military-aircraft/),
    [global.adsbexchange.com/VirtualRadar/mobile.html](https://global.adsbexchange.com/VirtualRadar/mobile.html)
-   Flightradar24, to track (mostly) civilian aircraft currently in the
    air around the world, archive goes 12 months back but (\$),
     [flightradar24.com](https://www.flightradar24.com/)
-   RadarBox, worldwide coverage, includes private and military jets,
    [radarbox24.com](https://www.radarbox24.com)
-   FlightView, [flightview.com](https://www.flightview.com/)

# Boats

-   MarineTraffic,
    [marinetraffic.com](https://www.marinetraffic.com/) 
-   VesselFinder,
    [vesselfinder.com](https://www.vesselfinder.com/) 
-   Fleet Min, [fleetmon.com](https://www.fleetmon.com/)

# Trains

-   France, full interactive map of the French railway system with live
    positions of trains, plus accuracy of schedule,
    [raildar.fr/\#lat=46.810&lng=6.880&zoom=6](http://www.raildar.fr/%23lat%3D46.810%26lng%3D6.880%26zoom%3D6)
-   Germany, full interactive map of current positions of Deutsche
    Bahn railway network,
    apps-bahn.de/bin/livemap/query-livemap.exe/dn?L=vs\_livefahrplan&livemap
     
-   Netherlands, full interactive map of the Dutch railway system,
    including live positions of trains,
    [http://spoorkaart.mwnn.nl](http://spoorkaart.mwnn.nl/) 

# Misc

-   WikiRoutes, public transport database,
    [wikiroutes.info](http://wikiroutes.info)

# Date and time
-   SunCalc, to make an approximation of the time of the day based on
    shadows,
    [suncalc.net](http://suncalc.net) 
-   Weather,
    [wolframalpha.com](http://www.wolframalpha.com) 


# Whois, IP lookups, website analysis
-   [Censys](https://censys.io/)
-   Central Ops, [CentralOps](http://centralops.net/)
-   Certificate search, [crt.sh](https://crt.sh) 
-   Complete DNS, historical DNS records,[completedns.com/dns-history](https://completedns.com/dns-history) 
-   BuildWith. Online database of web technologies used on website [buildwith.com](http://builtwith.com)
-   Domain Tools,[DomainTools](http://www.domaintools.com/)
-   IXMaps,[IXMaps](https://www.ixmaps.ca/explore.php)
-   [Network-Tools](http://network-tools.com/)
-   [Open Site Explorer](http://www.opensiteexplorer.org/)

#   People search
-   Peekyou,
    [peekyou.com](http://peekyou.com) 
-   Pipl, the world largest people search engine, find persons behind an e-mail address, social media username, or phone number,  [pipl.com](https://pipl.com/)
-   Yasni, [yasni.com](http://www.yasni.com/)
-   Zaba Search, only US, [zabasearch.com](http://www.zabasearch.com/)
-   [publicrecords.searchsystems.net](http://www.publicrecords.searchsystems.net)
-   [cemetery.canadagenweb.org/search.html](http://cemetery.canadagenweb.org/search.html)
-   [opencorporates.com](https://opencorporates.com/)

## Networks
-   [Robtex](https://www.robtex.com/)
-   [BGPView](https://bgpview.io/) to find networks and it's prefixes
-   [SearchIRC](http://search.mibbit.com/)
-   [Shodan Computer Search](http://www.shodanhq.com/)
-   [Utrace](http://en.utrace.de/)
-   [ViewDNS](http://viewdns.info/)
-   [D](http://whois.icann.org), [research.dnstrails.com](http://research.dnstrails.com)
-   [SpyOnWeb](http://research.dnstrails.com/)[,to retrieve websites by their Trackingcodes,](http://research.dnstrails.com/) 
-   Whois, for domain search and information, [whois.net](http://www.whois.net) or [whois.icann.org](http://whois.icann.org)

# Archiving
-   Archive.is, let’s you archive any webpage.
-   Let’s say you want to look whether old IS reports were archived, use
    a Google advanced search: make an \<IS search term\> justpaste.it
    site:archive.is and perhaps the site has been archived.

-   CachedView.com, Google Cached Pages for any web site. It is the
    ultimate internet cache.
-   Gruber, slideshare downloader,
    [http://grub.cballenar.me/](http://grub.cballenar.me/)
-   Historic Breach Database List,
    [https://publicdbhost.dmca.gripe/random/](https://publicdbhost.dmca.gripe/random/)
-   Wayback Machine, which archives websites
    [archive.org/web/web.php](http://archive.org/web/web.php) 

-   Download an entire website from the Wayback Machine,
    [github.com/hartator/wayback-machine-downloader](https://github.com/hartator/wayback-machine-downloader)

# Miscellaneous
-   Check for collaborative fact-checking, [checkmedia.org](http://www.checkdesk.org) 

-   Link to [user
    guide](https://drive.google.com/drive/u/1/folders/0B8ssHSpx1n0qcW9TYnNuYmx1VWc)
-   Bellingcat’s [Check team](https://checkmedia.org/)

-   Document Redaction, useful for removing potentially harmful content
    in Pdfs before viewing, like traceback,
    [github.com/firstlookmedia/pdf-redact-tools](https://github.com/firstlookmedia/pdf-redact-tools)
-   Geo IP Tool, check your own IP, handy to check if your VPN is
    working,
    [geoiptool.com](https://geoiptool.com)
-   Google Search Operators, such as searching for a specific filetype
    (e.g. PDF) or on a specific website,
    [googleguide.com/advanced\_operators\_](http://www.googleguide.com/advanced_operators_reference.html) 

-   Insecam, network live IP video cameras directory,
    [insecam.org/en/](http://www.insecam.org/en/) 
-   Knight Lab, make an interactive timeline of events,
    [timeline.knightlab.com](https://timeline.knightlab.com) 
-   LittleSis, a database of who-knows-who at the heights of business
    and government,
    [littlesis.org](http://littlesis.org/)
-   Lumen, the Lumen database collects and analyses legal complaints and
    requests for removal of online materials, helping Internet users to
    know their rights and understand the law. These data enables us to
    study the prevalence of legal threats and let Internet users see the
    source of content removals,
    [lumendatabase.org](https://lumendatabase.org/) 
-   Maltego tool,
    [paterva.com/web7](https://www.paterva.com/web7/)
-   Montage for collaborative working,
    [montage.storyful.com](https://montage.storyful.com/welcome?next%3D%252Fmy-projects)
-   OpenCorporates, database of companies in the world,         
-   People tracer,
    [peopletracer.co.uk](http://www.peopletracer.co.uk) 
-   Research sidekick Hunch.ly,
    [hunch.ly](http://www.hunch.ly/)
-   Visual Investigative Scenarios (VIS), a
    tool,[ ](https://vis.occrp.org/)
-   Wolfram Alpha, for any question and a computer-generated answer,
    [wolframalpha.com](http://www.wolframalpha.com) 
-   Zoopla, Search for property with the UK's leading resource. Browse
    houses and flats for sale and to rent, and find estate agents in any
    area,
    [zoopla.co.uk](https://www.zoopla.co.uk/) 

# Data visualization
-   DataBasic.io, web tools for beginners that introduce concepts of
    working with data,
     [databasic.io/en](https://www.databasic.io/en/) 
-   DataWrapper, easy to use chart and mapping tool,
    [datawrapper.de](https://www.datawrapper.de/) 
-   Google Fusion Tables, fusiontables.google.com  
-   Maptia,
    [maptia.com](https://maptia.com) 
-   Visual investigative
    scenarios, [vis.occrp.org](https://vis.occrp.org) 
-   RAWGraphs, free webtool to quickly visualize your data,
    [app.rawgraphs.io](http://app.rawgraphs.io/)

# Online security and privacy
-   Check for every digital service you use whether you have enabled two
    factor authentication (2FA),
    [twofactorauth.org](https://twofactorauth.org/) 
-   Security in a box guide:
    [https://securityinabox.org/en/](https://securityinabox.org/en/) 

# Search engines which protect privacy
-   DuckDuckGo, Internet search engine, protecting privacy,
    [duckduckgo.com](https://duckduckgo.com)
-   Qwant, Internet search engine, protecting privacy,
    [qwant.com](http://www.qwant.com) 


## Learn Forensics

- [Forensic challenges](https://www.amanhardikar.com/mindmaps/ForensicChallenges.html) - Mindmap of forensic challenges
- [OpenLearn](https://www.open.edu/openlearn/science-maths-technology/digital-forensics/content-section-0?active-tab=description-tab) - Digital forensic course

