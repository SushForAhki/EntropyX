```text
███████╗███╗   ██╗████████╗██████╗  ██████╗ ██████╗ ██╗   ██╗██╗  ██╗
██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔═══██╗██╔══██╗╚██╗ ██╔╝╚██╗██╔╝
█████╗  ██╔██╗ ██║   ██║   ██████╔╝██║   ██║██████╔╝ ╚████╔╝  ╚███╔╝ 
██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██║   ██║██╔═══╝   ╚██╔╝   ██╔██╗ 
███████╗██║ ╚████║   ██║   ██║  ██║╚██████╔╝██║        ██║   ██╔╝ ██╗
╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝        ╚═╝   ╚═╝  ╚═╝
```
![Version](https://img.shields.io/badge/Version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/Python-3.8%2B-green.svg)
![GUI](https://img.shields.io/badge/Aray%C3%BCz-PySide6-red.svg)

**EntropyX Security**, bilgisayarınızı virüslere ve zararlı programlara karşı korumak için tasarlanmış modern bir güvenlik programıdır. Arkasında yapay zeka ve farklı tarama motorları çalışır.

---

## 🚀 EntropyX Ne İşe Yarar ve Nasıl Çalışır?

Normal antivirüsler sadece önceden bildikleri virüsleri tanır. EntropyX ise bir dosyanın "şüpheli" davranıp davranmadığına bakarak daha önce hiç görülmemiş virüsleri bile yakalamaya çalışır. Bunu 3 farklı yöntemle yapar:

1. **Sezgisel (Heuristic) Tarama:** Dosyanın içine bakar. Eğer dosya gizlice başka programları çalıştırmaya, kendini bilgisayarın başlangıcına kopyalamaya veya kendini gizlemeye çalışıyorsa, buna bir "Risk Puanı" verir.
2. **Yapay Zeka (ML) Motoru:** Dosyanın boyutuna, içindeki anlamsız (karmaşık) karakterlerin yoğunluğuna (buna entropi denir) bakar. Yapay zeka bu matematiksel verilere dayanarak dosyanın zararlı olma ihtimalini yüzde (%) olarak hesaplar.
3. **YaraLite Motoru:** Korsanların sıklıkla kullandığı bilinen zararlı kod parçacıklarını ve şifreleri dosyaların içinde arar. 

### Diğer Güçlü Özellikleri
* **Gerçek Zamanlı Koruma:** Siz bilgisayarda gezinirken arka planda nöbet tutar. İnternetten yeni bir dosya indirdiğinizde anında tarar ve zararlıysa sizi uyarır.
* **Karantina Sistemi:** Zararlı bir dosya bulunduğunda onu bilgisayarınıza zarar veremeyeceği güvenli bir "kutuya" hapseder. İsterseniz bu dosyayı tamamen silebilir veya yanlış bir alarm olduğunu düşünüyorsanız geri yükleyebilirsiniz.

---

## 🛠️ Nasıl Kurulur? (Adım Adım)

Bu program Python dili ile yazılmıştır. Bilgisayarınızda çalıştırabilmek için şu adımları izlemelisiniz:

**Adım 1: Python'ı Yükleyin**
Bilgisayarınızda Python yüklü değilse, python.org adresinden indirip kurun. Kurulum sırasında alt kısımdaki **"Add Python to PATH"** kutucuğunu işaretlemeyi kesinlikle unutmayın.

**Adım 2: Gerekli Ek Paketleri İndirin**
Programın arayüzünün ve yapay zeka kısımlarının çalışması için bazı ek dosyalara ihtiyacı var. 
Klavyenizden `Windows + R` tuşlarına basın, `cmd` yazıp Enter'a basın (Siyah bir komut ekranı açılacak). Oraya şu kodu yapıştırıp Enter'a basın:

```bash
pip install PySide6 scikit-learn numpy watchdog
```
Bu işlem internet hızınıza bağlı olarak 1-2 dakika sürebilir, bitmesini bekleyin.


Adım 3: Programı Çalıştırın
Komut ekranında programın bulunduğu klasöre gidin ve programı başlatın:

Bash
python entropyx.py
💻 Menüler Ne İşe Yarıyor?
Programı açtığınızda solda bir menü göreceksiniz. İşte bu menülerin anlamları:

📊 Dashboard (Ana Ekran): Bilgisayarınızın genel durumunu görürsünüz. Kaç dosya taranmış, kaç virüs engellenmiş gibi özet bilgiler burada yer alır.

🔍 Tarama: Bilgisayarınızı taratacağınız yer burasıdır. İsterseniz sadece belirli bir klasörü (Özel Tarama), isterseniz tüm bilgisayarı taratabilirsiniz.

🛡️ Koruma: Arka planda çalışan nöbetçi sistemin ayarlarıdır. Hangi klasörlerin (Örneğin sadece İndirilenler ve Masaüstü) otomatik izleneceğini buradan seçebilirsiniz.

⚠️ Tespitler: Programın zararlı veya şüpheli bulduğu dosyaların listelendiği sabıka kaydı ekranıdır.

🔐 Karantina: Bilgisayardan izole edilen, hapse atılan dosyaların tutulduğu yer. Buradan dosyaları sonsuza dek silebilirsiniz.

📋 Loglar: Programın arka planda ne yaptığını adım adım yazılı olarak anlattığı günlük defteridir.

👨‍💻 Geliştirici Notu
Bu proje, siber güvenlik kavramlarını (zararlı yazılım analizi, yapay zeka ile tespit) pratik bir şekilde uygulamak için geliştirilmiştir.

Geliştirici: SushForAhki

Lisans: MIT Lisansı (Açık Kaynak)
