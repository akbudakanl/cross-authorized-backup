# Vault Extension: Offline SSH CA & Console Break-Glass Lockdown

**Classification:** ARCHITECTURE EXTENSION / OPTIONAL HARDENING

Bu eklenti dosyası, Canonical yapıya entegre edilmiş olan Offline CA ve Console Lockdown mimarisinin geçmişini ve halen opsiyonel olan fiziksel kağıt (Break-Glass) kurtarma konseptini açıklamaktadır.

## Söz konusu uygulama öncesi güncel olmayan versiyon

Standart mimarinin eski versiyonunda, bir VPS sunucusunun SSH erişimi Ed25519 anahtarı ve TOTP (Time-Based One-Time Password) ile korunmaktaydı. Bu yapıda, `/etc/ssh/sshd_config` dosyası `AuthenticationMethods publickey,keyboard-interactive` olarak ayarlanır ve `google-authenticator` gibi bir PAM modülü kullanılırdı.

Ancak TOTP (6 haneli şifre) matematiksel olarak 1.000.000'da 1 tahmin edilebilirliğe sahiptir. Ayrıca eski yapıda Bulut Sağlayıcıların yönetim konsolları (AWS Session Manager, OCI Cloud Shell) OS seviyesindeki SSH korumalarını bypass edebilme potansiyeli taşıdığı halde açık bırakılıyordu. Bu durum, "Sıfır Güven" (Zero-Trust) zincirinde zayıf halkalar oluşturuyordu.

## Güncellenmiş versiyon

Mevcut Canonical (varsayılan) mimaride TOTP ve Bulut Sağlayıcı Web Konsolu bağımlılıkları tamamen ortadan kaldırılmıştır. Bu güncel sürümde erişim tamamen merkeziyetsiz, hava boşluklu (air-gapped) bir sertifika otoritesine (Telefon) devredilmiştir.

1. **İçeri Giriş Kapısı (SSH Offline CA):** Sadece Tailscale ağı içinden gelen, PC'nin SSH anahtarına sahip olan ve bu anahtarı bağlantı anında **Telefondaki (Offline/Air-Gapped) Sertifika Otoritesine (CA) QR Kod ile imzalatan** kişi içeri girebilir.
    - Telefon kendi CA anahtarını üretir ve asla dışarı çıkarmaz. Sadece `ca.pub` VPS'e kopyalanır.
    - `sshd_config` üzerinde `TrustedUserCAKeys /etc/ssh/ca.pub` kullanılarak sunucu TOTP sormayı bırakır ve sadece bu imzalı sertifikayı kabul eder.
    - SSH isteği sırasında public key QR kod ile telefona okutulur, imzalanan sertifika yine QR kod ile PC'ye alınarak giriş yapılır.

2. **Arka Kapı (Cloud Console Lockdown):** Bulut sağlayıcının sunduğu Admin Konsoluna (VNC/Serial TTY) girilse bile işletim sistemi hiçbir tuş vuruşuna yanıt vermez.
    - `sudo systemctl mask getty@tty1.service` ve `serial-getty@ttyS0.service` komutlarıyla terminal ekranları sağırlaştırılmıştır.

> [!WARNING]
> **Tam Veri Kaybı Riski (Acımasız Kilitlenme):** Bu güncel mimari, yöneticiyi (Admin) kendi sunucusuna karşı da acımasızca kilitler. OCI Web Konsolu kilitlendiği için, Telefon (CA cihazı) kırılırsa veya kaybolursa, kiraladığınız VPS'lere erişmek matematiksel ve fiziksel olarak **imkansızdır**. Verilerinizi kaybedersiniz.

## Opsiyonel geliştirme fikri

Konsol sağırlaştırıldığı için SSH sisteminin (CA) çökmesi veya kaybedilmesi durumunda **opsiyonel** olarak aşağıdaki "Kağıtta Saklanan Admin Console Erişim Anahtarı (Break-Glass)" yapısı kurulabilir. Bu geliştirme Canonical dosyasına dahil edilmemiştir ve uygulanması tamamen isteğe bağlıdır.

### Offline Break-Glass (Kağıttaki Acil Durum Şifresi)

Sistem kilitlendiğinde tek kurtuluş yolunuz bootloader (GRUB) üzerinden `single-user mode`'a düşerek konsol erişimini geri kazanmaktır.

1. **PBKDF2 Şifresinin Üretilmesi (Fiziksel Kağıt):**
   - Tamamen rastgele, 64-128 karakter uzunluğunda bir şifre üretilir.
   - Bu şifre **asla** bir şifre yöneticisine kaydedilmez, doğrudan fiziksel bir kağıda/çelik plakaya yazılıp kasaya kaldırılır.

2. **GRUB Bootloader'ın Kilitlenmesi:**
   - Üretilen şifrenin PBKDF2 özeti çıkarılır ve GRUB yapılandırmasına gömülür:
     ```bash
     grub2-setpassword
     # (Kağıttaki şifre girilir, sistem hash'ini alır ve kaydeder)
     ```

**Acil bir durum olursa:**
1. Bulut paneline girilir.
2. Sunucu yeniden başlatılır (Reboot).
3. Açılış (Boot) ekranındayken acil durum kağıdı alınır.
4. GRUB ekranında "E" tuşuna basılıp kağıttaki şifre girilir ve sistem `single-user mode` (veya `init=/bin/bash`) olarak başlatılarak konsol erişimi geri kazanılır.

Bu sayede, bulut sağlayıcınız hacklense bile saldırganın o fiziksel kağıda sahip olmadan sunucunun işletim sistemine veya verilerine erişmesi engellenmiş olur.
