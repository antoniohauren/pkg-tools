use super::*;

fn local_self() -> Vec<u8> {
    fn put64(b: &mut [u8], at: usize, n: u64) {
        b[at..at + 8].copy_from_slice(&n.to_be_bytes());
    }
    let rap = Rap::from_bytes(&[7; 16]).unwrap();
    let mut b = vec![0; 704];
    b[..4].copy_from_slice(b"SCE\0");
    put32(&mut b, 4, 2);
    b[9] = 10;
    b[11] = 1;
    put32(&mut b, 12, 256);
    put64(&mut b, 16, 640);
    put64(&mut b, 40, 104);
    put32(&mut b, 116, 8);
    put64(&mut b, 88, 136);
    put64(&mut b, 96, 144);
    put32(&mut b, 136, 3);
    put32(&mut b, 140, 144);
    b[152..156].copy_from_slice(b"NPD\0");
    put32(&mut b, 160, 2);
    b[288..304].fill(1);
    b[320..336].fill(2);
    put64(&mut b, 352, 560);
    put32(&mut b, 364, 1);
    put32(&mut b, 368, 8);
    put64(&mut b, 384, 640);
    put64(&mut b, 392, 64);
    put32(&mut b, 400, 2);
    put32(&mut b, 408, 2);
    put32(&mut b, 416, 3);
    put32(&mut b, 420, 6);
    put32(&mut b, 424, 7);
    put32(&mut b, 428, 1);
    b[464..528].fill(9);
    b[528..544].fill(3);
    b[544..560].fill(4);
    b[640..].fill(42);
    let hash = hmac(&b[464..528], &b[640..]);
    b[432..452].copy_from_slice(&hash);
    ctr(&[3; 16], [4; 16], &mut b[640..]);
    ctr(&[1; 16], [2; 16], &mut b[352..640]);
    cbc(
        &hex::<32>("03c21ad78fbb6a3d425e9aab1298f9fd70e29fd4e6e3a3c151205da50c413de4"),
        hex("0a99d4d4f8301a88052d714ad2fb565e"),
        &mut b[288..352],
        false,
    );
    cbc(&aes(&KLIC, rap.key, true), [0; 16], &mut b[288..352], false);
    b
}

#[test]
fn self_rap_rewrap_preserves_sections_and_rejects_damage() {
    let source = local_self();
    let mut labeled = source.clone();
    labeled[168..216].fill(b'A');
    assert_eq!(self_content_id(&labeled[..]).unwrap(), [b'A'; 48]);
    assert!(self_content_id(&labeled[..639]).is_err());
    labeled[140..144].copy_from_slice(&0u32.to_be_bytes());
    assert!(self_content_id(&labeled[..]).is_err());
    let rap = Rap::from_bytes(&[7; 16]).unwrap();
    let mut output = source.clone();
    let sections = convert_self(&mut output, &rap, &[0; 48], "EBOOT.BIN", &|| false).unwrap();
    assert_eq!(sections, vec![vec![42; 64]]);
    assert_eq!(&output[640..], &source[640..]);
    assert_eq!(u32_at(&output, 160).unwrap(), 3);
    cbc(
        &aes(&KLIC, FREE, true),
        [0; 16],
        &mut output[288..352],
        true,
    );
    cbc(
        &hex::<32>("03c21ad78fbb6a3d425e9aab1298f9fd70e29fd4e6e3a3c151205da50c413de4"),
        hex("0a99d4d4f8301a88052d714ad2fb565e"),
        &mut output[288..352],
        true,
    );
    assert_eq!(&output[288..304], &[1; 16]);
    assert_eq!(&output[304..320], &[0; 16]);
    for length in (0..source.len()).step_by(7) {
        assert!(
            convert_self(
                &mut source[..length].to_vec(),
                &rap,
                &[0; 48],
                "EBOOT.BIN",
                &|| false
            )
            .is_err()
        );
    }
    assert!(
        convert_self(
            &mut source.clone(),
            &Rap::from_bytes(&[8; 16]).unwrap(),
            &[0; 48],
            "EBOOT.BIN",
            &|| false
        )
        .is_err()
    );
    let mut damaged = source.clone();
    damaged[640] ^= 1;
    assert!(convert_self(&mut damaged, &rap, &[0; 48], "EBOOT.BIN", &|| false).is_err());
    let mut unsupported = source.clone();
    unsupported[9] = 0xff;
    assert!(matches!(
        convert_self(&mut unsupported, &rap, &[0; 48], "EBOOT.BIN", &|| false),
        Err(Error::Unsupported(_))
    ));
    assert!(matches!(
        convert_self(&mut source.clone(), &rap, &[0; 48], "EBOOT.BIN", &|| true),
        Err(Error::Cancelled)
    ));
}

pub(crate) fn local_edat(interleaved: bool) -> (Vec<u8>, Vec<u8>) {
    let key = Rap::from_bytes(&[7; 16]).unwrap().key;
    let wrap = hex("be959ca8308defa2e5e180c63712a9ae");
    let plain: Vec<u8> = (0..1501).map(|i| (i % 251) as u8).collect();
    let mut out = vec![0; 0x100];
    out[..4].copy_from_slice(b"NPD\0");
    put32(&mut out, 4, 3);
    put32(&mut out, 8, 2);
    let mut title = vec![0; 48];
    title.extend_from_slice(b"test.edat");
    out[80..96].copy_from_slice(&cmac(&OMAC3, &title));
    let devhash = cmac(&xor(FREE, OMAC2), &out[..96]);
    out[96..112].copy_from_slice(&devhash);
    put32(&mut out, 128, if interleaved { 0x3c } else { 0x0c });
    put32(&mut out, 132, 1024);
    out[136..144].copy_from_slice(&(plain.len() as u64).to_be_bytes());
    let mut metadata = Vec::new();
    let mut payloads = Vec::new();
    for (i, part) in plain.chunks(1024).enumerate() {
        let mut seed = devhash;
        put32(&mut seed, 12, i as u32);
        let bk = aes(&key, seed, false);
        let ek = aes(&wrap, bk, true);
        let mut payload = part.to_vec();
        payload.resize(part.len().div_ceil(16) * 16, 0);
        cbc(&ek, [0; 16], &mut payload, false);
        if interleaved {
            let hk = aes(&wrap, aes(&key, bk, false), true);
            let mut hkey = [0; 20];
            hkey[..16].copy_from_slice(&hk);
            let hash = hmac(&hkey, &payload);
            let mut md = [0; 32];
            md[16..20].copy_from_slice(&hash[16..20]);
            for j in 0..16 {
                md[j] = hash[j] ^ md[j + 16];
            }
            metadata.extend_from_slice(&md);
            out.extend_from_slice(&md);
            out.extend_from_slice(&payload);
        } else {
            metadata.extend_from_slice(&cmac(&ek, &payload));
            payloads.extend_from_slice(&payload);
        }
    }
    if !interleaved {
        out.extend_from_slice(&metadata);
        out.extend_from_slice(&payloads);
    }
    out[144..160].copy_from_slice(&cmac(&aes(&wrap, key, true), &metadata));
    let hash = cmac(&aes(&wrap, key, true), &out[..160]);
    out[160..176].copy_from_slice(&hash);
    (out, plain)
}

#[test]
fn authenticated_edat_conversion_and_failures() {
    let rap = Rap::from_bytes(&[7; 16]).unwrap();
    let wrong = Rap::from_bytes(&[8; 16]).unwrap();
    for interleaved in [false, true] {
        let (input, plain) = local_edat(interleaved);
        let out = convert_edat(&input, &rap, &[0; 48], "test.edat", &[], &|| false)
            .unwrap()
            .unwrap();
        assert_eq!(u32_at(&out, 8).unwrap(), 3);
        let wrap = hex("be959ca8308defa2e5e180c63712a9ae");
        let key = aes(&wrap, FREE, true);
        assert_eq!(cmac(&key, &out[..160]), &out[160..176]);
        assert_eq!(cmac(&key, &out[256..288]), &out[144..160]);
        let mut decoded = Vec::new();
        for i in 0..2 {
            let length = 1024.min(plain.len() - i * 1024);
            let start = 288 + i * 1024;
            let end = start + length.div_ceil(16) * 16;
            let mut seed = block(&out, 96).unwrap();
            put32(&mut seed, 12, i as u32);
            let key = aes(&wrap, aes(&FREE, seed, false), true);
            let mut data = out[start..end].to_vec();
            assert_eq!(cmac(&key, &data), &out[256 + i * 16..272 + i * 16]);
            cbc(&key, block(&out, 64).unwrap(), &mut data, true);
            decoded.extend_from_slice(&data[..length]);
        }
        assert_eq!(decoded, plain);
        assert!(convert_edat(&input, &wrong, &[0; 48], "test.edat", &[], &|| false).is_err());
        assert!(convert_edat(&input, &rap, &[1; 48], "test.edat", &[], &|| false).is_err());
        assert!(convert_edat(&input, &rap, &[0; 48], "renamed.edat", &[], &|| false).is_err());
        assert!(matches!(
            convert_edat(&input, &rap, &[0; 48], "test.edat", &[], &|| true),
            Err(Error::Cancelled)
        ));
        let mut broken = input.clone();
        let end = broken.len() - 1;
        broken[end] ^= 1;
        assert!(convert_edat(&broken, &rap, &[0; 48], "test.edat", &[], &|| false).is_err());
        for length in 0..256 {
            assert!(
                convert_edat(&input[..length], &rap, &[0; 48], "test.edat", &[], &|| {
                    false
                })
                .is_err()
            );
        }
    }
    for length in [0, 15, 17, 32] {
        assert!(Rap::from_bytes(&vec![0; length]).is_err());
    }
}
