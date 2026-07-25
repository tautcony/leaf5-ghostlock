> **文档类型**: 无关文档 | **状态**: ⚠️ 与 Leaf5 GhostLock 分析无关 — 此为 Boox P6 Pro (SM7225/bitra_SDM) EDL printgpt 原始输出 | **采集日期**: ~2025-12

Keystone library is missing (optional).
Qualcomm Sahara / Firehose Client V3.62 (c) B.Kerler 2018-2025.
main - Using loader palma2pro.bin ...
main - Waiting for the device
main - Device detected :)
sahara - Protocol version: 2, Version supported: 1
main - Mode detected: sahara
sahara -
Version 0x2
------------------------
HWID:              0x0013f0e100000000 (MSM_ID:0x0013f0e1,OEM_ID:0x0000,MODEL_ID:0x0000)
CPU detected:      "bitra_SDM"
PK_HASH:           0xd40eee56f3194665574109a39267724ae7944134cd53cb767e293d3c40497955bc8a4519ff992b031fadc6355015ac87
Serial:            0x25d695ba

sahara - Protocol version: 2, Version supported: 1
sahara - Uploading loader palma2pro.bin ...
sahara - 64-Bit mode detected.
sahara - Loader successfully uploaded.
main - Trying to connect to firehose loader ...
firehose - INFO: Binary build date: Aug 21 2020 @ 09:02:30
firehose - INFO: Binary build date: Aug 21 2020 @ 09:02:30
firehose - INFO: Chip serial num: 634820026 (0x25d695ba)
firehose - INFO: Supported Functions (17):
firehose - INFO: program
firehose - INFO: read
firehose - INFO: nop
firehose - INFO: patch
firehose - INFO: configure
firehose - INFO: setbootablestoragedrive
firehose - INFO: erase
firehose - INFO: power
firehose - INFO: firmwarewrite
firehose - INFO: getstorageinfo
firehose - INFO: benchmark
firehose - INFO: emmc
firehose - INFO: ufs
firehose - INFO: fixgpt
firehose - INFO: getsha256digest
firehose - INFO: getvar
firehose - INFO: dump
firehose - INFO: End of supported functions 17
firehose_client
firehose_client - [LIB]: No --memory option set, we assume "UFS" as default ..., if it fails, try using "--memory" with "UFS","NAND" or "spinor" instead !
firehose
firehose - [LIB]: Couldn't detect MaxPayloadSizeFromTargetinBytes
firehose
firehose - [LIB]: Couldn't detect TargetName
firehose - TargetName=Unknown
firehose - MemoryName=UFS
firehose - Version=1
firehose - Trying to read first storage sector...
firehose - Running configure...
firehose
firehose - [LIB]: Memory type UFS doesn't seem to match (Failed to init). Trying to use eMMC instead.
firehose
firehose - [LIB]: Couldn't detect MaxPayloadSizeFromTargetinBytes
firehose
firehose - [LIB]: Couldn't detect TargetName
firehose - TargetName=Unknown
firehose - MemoryName=eMMC
firehose - Version=1
firehose - Trying to read first storage sector...
firehose - Running configure...
firehose
firehose - [LIB]: Couldn't detect MaxPayloadSizeFromTargetinBytes
firehose
firehose - [LIB]: Couldn't detect TargetName
firehose - TargetName=Unknown
firehose - MemoryName=eMMC
firehose - Version=1
firehose - Trying to read first storage sector...
firehose - Running configure...
firehose - Storage report:
firehose - total_blocks:122126336
firehose - block_size:512
firehose - page_size:512
firehose - num_physical:4
firehose - manufacturer_id:223
firehose - serial_num:2889092358
firehose - fw_version:48734822444564496
firehose - mem_type:eMMC
firehose - prod_name:SCA64G
firehose_client - Supported functions:
-----------------
program,read,nop,patch,configure,setbootablestoragedrive,erase,power,firmwarewrite,getstorageinfo,benchmark,emmc,ufs,fixgpt,getsha256digest,getvar,dump

Parsing Lun 0:

GPT Table:
-------------
xbl_a:               Offset 0x0000000004000000, Length 0x0000000000380000, Flags 0x107f000000000000, UUID 34c0392e-b267-f459-e230-d1cc01a3a868, Type 0xdea0ba2c, Active True
xbl_b:               Offset 0x0000000004380000, Length 0x0000000000380000, Flags 0x107b000000000000, UUID e08c63a1-688e-d664-355a-8e3d7438beeb, Type 0x77036cd4, Active False
xbl_config_a:        Offset 0x0000000008000000, Length 0x0000000000020000, Flags 0x007f000000000000, UUID 330e31ca-4fe6-c2f4-8e77-c0366ad22109, Type 0x5a325ae4, Active True
xbl_config_b:        Offset 0x0000000008020000, Length 0x0000000000020000, Flags 0x007b000000000000, UUID fae8265a-6f9d-2a59-e1cf-d824f6411546, Type 0x77036cd4, Active False
tz_a:                Offset 0x000000000c000000, Length 0x0000000000400000, Flags 0x107f000000000000, UUID afaa2bf0-94f8-d25a-8e40-dc7331a54990, Type 0xa053aa7f, Active True
tz_b:                Offset 0x0000000010000000, Length 0x0000000000400000, Flags 0x007b000000000000, UUID 588a4e0d-0f0a-83fd-c372-9b5b417b5dba, Type 0x77036cd4, Active False
multiimgoem_a:       Offset 0x0000000014000000, Length 0x0000000000008000, Flags 0x107f000000000000, UUID 215aaef2-713d-467c-1edb-ca3076063811, Type 0xe126a436, Active True
multiimgoem_b:       Offset 0x0000000018000000, Length 0x0000000000008000, Flags 0x007b000000000000, UUID 24794f5f-1bb9-bea6-dfe8-ca29089d2d37, Type 0x77036cd4, Active False
aop_a:               Offset 0x000000001c000000, Length 0x0000000000080000, Flags 0x107f000000000000, UUID 6c0ed448-729a-0f79-2f30-0cb0a24bd6dd, Type 0xd69e90a5, Active True
aop_b:               Offset 0x0000000020000000, Length 0x0000000000080000, Flags 0x007b000000000000, UUID ce3591ee-85e2-7f32-7371-f91bf59dd52c, Type 0x77036cd4, Active False
hyp_a:               Offset 0x0000000024000000, Length 0x0000000000080000, Flags 0x107f000000000000, UUID 2935208b-b5dc-1e9a-59b7-154278092e0c, Type 0xe1a6a689, Active True
hyp_b:               Offset 0x0000000028000000, Length 0x0000000000080000, Flags 0x007b000000000000, UUID a229acbd-ed39-6f89-d1d8-a5d193bf3d02, Type 0x77036cd4, Active False
boot_a:              Offset 0x0000000028080000, Length 0x0000000006000000, Flags 0x0077000000000000, UUID 244dc43a-c8d2-b12b-7a45-39050dae4a19, Type 0x20117f86, Active True
boot_b:              Offset 0x000000002e080000, Length 0x0000000006000000, Flags 0x0073000000000000, UUID b6bea7eb-1608-cbfd-4cdb-bce334010455, Type 0x77036cd4, Active False
super:               Offset 0x0000000034080000, Length 0x0000000180000000, Flags 0x0000000000000000, UUID f9d6b842-784e-06c0-70ee-39f675315680, Type 0x89a12de1, Active False
recovery_a:          Offset 0x00000001b4080000, Length 0x0000000006000000, Flags 0x0004000000000000, UUID be26d8bd-aac6-4f27-9ef3-cfeef24fc102, Type 0xd504d6db, Active True
recovery_b:          Offset 0x00000001ba080000, Length 0x0000000006000000, Flags 0x0000000000000000, UUID fd6dcb6f-09af-3a67-5699-8612be75b7ee, Type 0x352b8083, Active False
vbmeta_system_a:     Offset 0x00000001c4000000, Length 0x0000000000010000, Flags 0x1004000000000000, UUID 7c80251e-99f8-18df-9bdd-401d248b15a7, Type 0x1344859d, Active True
vbmeta_system_b:     Offset 0x00000001c4010000, Length 0x0000000000010000, Flags 0x1000000000000000, UUID 00d96f48-0301-c421-e113-96eeb9cd26ba, Type 0xfe3ab853, Active False
metadata:            Offset 0x00000001c8000000, Length 0x0000000001000000, Flags 0x0000000000000000, UUID 6551a4f5-bd4a-6e4d-0f48-c0799fcd51e3, Type 0x988a98c9, Active False
keymaster_a:         Offset 0x00000001cc000000, Length 0x0000000000080000, Flags 0x107f000000000000, UUID 8b65f43f-0c6d-9098-1878-3a34fb022eca, Type 0xa11d2a7c, Active True
keymaster_b:         Offset 0x00000001cc080000, Length 0x0000000000080000, Flags 0x107b000000000000, UUID a9e196cc-b629-3abd-f6be-3386566990e3, Type 0x77036cd4, Active False
mdtpsecapp_a:        Offset 0x00000001cc100000, Length 0x0000000000400000, Flags 0x107f000000000000, UUID 30ea172f-0cc2-effe-299a-f44c03fdd327, Type 0xea02d680, Active True
mdtpsecapp_b:        Offset 0x00000001cc500000, Length 0x0000000000400000, Flags 0x107b000000000000, UUID 3f35fdd4-d235-7a27-3df2-af7ec77187e3, Type 0x77036cd4, Active False
mdtp_a:              Offset 0x00000001cc900000, Length 0x0000000002000000, Flags 0x107f000000000000, UUID a6ca8deb-eb30-41ab-7237-8234a077ab2d, Type 0x3878408a, Active True
mdtp_b:              Offset 0x00000001ce900000, Length 0x0000000002000000, Flags 0x107b000000000000, UUID e226049f-6d8d-7b4b-645f-84b2ebfcabe5, Type 0x77036cd4, Active False
modem_a:             Offset 0x00000001d0900000, Length 0x000000000c300000, Flags 0x107f000000000000, UUID 8b0e9e25-957e-fe58-002a-723713c79bea, Type EFI_BASIC_DATA, Active True
modem_b:             Offset 0x00000001dcc00000, Length 0x000000000c300000, Flags 0x107b000000000000, UUID bfd8e922-9735-1dc0-13e8-2fefe969095f, Type 0x77036cd4, Active False
core_nhlos_a:        Offset 0x00000001e8f00000, Length 0x000000000aa00000, Flags 0x1004000000000000, UUID 6ace8751-bcd8-056a-29fa-d0c5df4d3eed, Type 0x6690b4ce, Active True
core_nhlos_b:        Offset 0x00000001f3900000, Length 0x000000000aa00000, Flags 0x1000000000000000, UUID ae7330ff-68c5-f31d-8ce9-349480ada36e, Type 0x77036cd4, Active False
dsp_a:               Offset 0x00000001fe300000, Length 0x0000000004000000, Flags 0x107f000000000000, UUID 7e414c23-3908-e5f0-9879-2740ba3feaec, Type 0x7efe5010, Active True
dsp_b:               Offset 0x0000000202300000, Length 0x0000000004000000, Flags 0x107b000000000000, UUID 18fb952d-5d2b-73c6-19d5-1511ee90bbe7, Type 0x77036cd4, Active False
abl_a:               Offset 0x0000000206300000, Length 0x0000000000100000, Flags 0x107f000000000000, UUID dd18eb10-a7d1-b431-c8c5-995d9ca7812f, Type 0xbd6928a1, Active True
abl_b:               Offset 0x0000000206400000, Length 0x0000000000100000, Flags 0x107b000000000000, UUID 650a89a7-02c8-befb-4f87-07fac0944ee8, Type 0x77036cd4, Active False
ddr:                 Offset 0x0000000206500000, Length 0x0000000000100000, Flags 0x1000000000000000, UUID cab81406-ff69-a5d8-c3b0-f0078be4cfb5, Type 0x20a0c19c, Active False
bluetooth_a:         Offset 0x0000000206600000, Length 0x0000000000100000, Flags 0x107f000000000000, UUID 52a0ee11-bd62-942c-55a8-c5e46fec67e7, Type 0x6cb747f1, Active True
bluetooth_b:         Offset 0x0000000206700000, Length 0x0000000000100000, Flags 0x107b000000000000, UUID 308912d3-34cd-c3e5-bcec-7ad0c61ead3b, Type 0x77036cd4, Active False
ssd:                 Offset 0x0000000208000000, Length 0x0000000000002000, Flags 0x0000000000000000, UUID 4b118528-98e2-eb91-37c8-3ea74fcb0d45, Type 0x2c86e742, Active False
dtbo_a:              Offset 0x0000000208002000, Length 0x0000000001800000, Flags 0x007f000000000000, UUID 700321c6-d53b-b819-1fc7-c6011941fe06, Type 0x24d0d418, Active True
dtbo_b:              Offset 0x0000000209802000, Length 0x0000000001800000, Flags 0x007b000000000000, UUID 8d7eddae-24ec-f1d9-61f3-74f7b384da3b, Type 0x77036cd4, Active False
imagefv_a:           Offset 0x000000020b002000, Length 0x0000000000200000, Flags 0x007f000000000001, UUID b518e58d-a924-1f64-cf73-550b62597a96, Type 0x17911177, Active True
imagefv_b:           Offset 0x000000020b202000, Length 0x0000000000200000, Flags 0x007b000000000001, UUID 39236c74-8c29-9d5a-0041-1c60a105518a, Type 0x77036cd4, Active False
uefisecapp_a:        Offset 0x000000020b402000, Length 0x0000000000200000, Flags 0x0004000000000000, UUID fe77db82-bfc3-b2da-f215-693621c7556b, Type 0xbe8a7e08, Active True
uefisecapp_b:        Offset 0x000000020b602000, Length 0x0000000000200000, Flags 0x0000000000000000, UUID 9d275efd-64e8-7d40-6e59-6abf174c901b, Type 0x77036cd4, Active False
persist:             Offset 0x000000020b802000, Length 0x0000000002000000, Flags 0x0000000000000000, UUID aba9804c-e9a6-a875-a529-3ae4dfe6e165, Type 0x6c95e238, Active False
misc:                Offset 0x000000020d802000, Length 0x0000000000100000, Flags 0x0000000000000000, UUID 9682d74b-d5ac-f8cf-6fe6-4602966e948a, Type 0x82acc91f, Active False
keystore:            Offset 0x000000020d902000, Length 0x0000000000080000, Flags 0x0000000000000000, UUID 75838bde-5258-7069-df45-90f61f408b99, Type 0xde7d4029, Active False
devcfg_a:            Offset 0x000000020d982000, Length 0x0000000000020000, Flags 0x007f000000000000, UUID 6c1f5643-173a-02cb-30de-9eb335281a68, Type 0xf65d4b16, Active True
devcfg_b:            Offset 0x000000020d9a2000, Length 0x0000000000020000, Flags 0x007b000000000000, UUID b72e83da-bbdb-f5ce-29e8-765bb8580ee5, Type 0x77036cd4, Active False
featenabler_a:       Offset 0x000000020d9c2000, Length 0x0000000000020000, Flags 0x0004000000000000, UUID 71ec9b5c-7a26-a3ed-c34d-edbe69a4f538, Type 0x741813d2, Active True
questdatafv:         Offset 0x0000000210000000, Length 0x0000000001000000, Flags 0x1000000000000000, UUID 2259ea27-6fbc-e099-f443-3a3c906c01fb, Type 0x7f86d79a, Active False
featenabler_b:       Offset 0x0000000214000000, Length 0x0000000000020000, Flags 0x0000000000000000, UUID 03a1547b-f021-1fd9-3b32-13d8f24586c7, Type 0x77036cd4, Active False
qupfw_a:             Offset 0x0000000214020000, Length 0x0000000000014000, Flags 0x007f000000000000, UUID 8bc6c3ae-b369-d8d4-3c8d-75f213074706, Type 0x21d1219f, Active True
qupfw_b:             Offset 0x0000000214034000, Length 0x0000000000014000, Flags 0x007b000000000000, UUID 4400ec97-0848-a3cf-dfb2-3932591e9add, Type 0x77036cd4, Active False
frp:                 Offset 0x0000000214048000, Length 0x0000000000080000, Flags 0x0000000000000000, UUID be6dab41-7a0c-de28-8513-903aeff60f9e, Type 0x91b72d4d, Active False
rawdump:             Offset 0x00000002140c8000, Length 0x0000000008000000, Flags 0x0000000000000000, UUID 6a83acbb-05a6-b9c0-2fbe-2f3abd1afe28, Type 0x66c9b323, Active False
devinfo:             Offset 0x0000000220000000, Length 0x0000000000001000, Flags 0x1000000000000000, UUID af35da47-cf17-e67e-2177-32fbe32115d9, Type 0x65addcf4, Active False
dip:                 Offset 0x0000000220001000, Length 0x0000000000100000, Flags 0x1000000000000000, UUID 6c3061d2-4703-5637-9f41-a5de01f03f7d, Type 0x4114b077, Active False
apdp:                Offset 0x0000000224000000, Length 0x0000000000040000, Flags 0x0000000000000000, UUID e3d01951-b427-6dcf-3f26-904fc2c6fb05, Type 0xe6e98da2, Active False
spunvm:              Offset 0x0000000224040000, Length 0x0000000000800000, Flags 0x0000000000000000, UUID fd7842ad-3fe2-a9f9-2b69-f6f62f981bf6, Type 0xe42e2b4c, Active False
splash:              Offset 0x0000000224840000, Length 0x00000000020a4000, Flags 0x0000000000000000, UUID 591ce871-6c35-5293-1723-b2891fdd1b1c, Type 0xad99f201, Active False
limits:              Offset 0x0000000228000000, Length 0x0000000000001000, Flags 0x1000000000000000, UUID 9c8a90be-1cd4-590c-dca0-646c80b83250, Type 0x10a0c19c, Active False
limits-cdsp:         Offset 0x0000000228001000, Length 0x0000000000001000, Flags 0x1000000000000000, UUID 5485426b-6646-9840-d3ee-dddc987ff942, Type 0x545d3707, Active False
toolsfv:             Offset 0x0000000228002000, Length 0x0000000000100000, Flags 0x1000000000000000, UUID 01d3d552-8cc4-d023-42de-05d7765d2eeb, Type 0x97745aba, Active False
logfs:               Offset 0x000000022c000000, Length 0x0000000000800000, Flags 0x0000000000000000, UUID e38f8430-8d01-b7ae-39f4-aa0a28522106, Type 0xbc0330eb, Active False
cateloader:          Offset 0x000000022c800000, Length 0x0000000000200000, Flags 0x0000000000000000, UUID 4a84f465-210f-a43b-5a7a-34c453d80cd6, Type 0xaa9a5c4c, Active False
logdump:             Offset 0x000000022ca00000, Length 0x0000000004000000, Flags 0x0000000000000000, UUID 0ed60b66-d72d-c4c9-515c-9c697cbce5c7, Type 0x5af80809, Active False
vbmeta_a:            Offset 0x0000000234000000, Length 0x0000000000010000, Flags 0x107f000000000000, UUID 7c376818-8c9b-1b42-f2ac-d39b461bb5a3, Type 0x4b7a15d6, Active True
vbmeta_b:            Offset 0x0000000234010000, Length 0x0000000000010000, Flags 0x107b000000000000, UUID 861e4d71-21c4-2d25-fb60-9e1c7d90217d, Type 0x77036cd4, Active False
storsec:             Offset 0x0000000234020000, Length 0x0000000000020000, Flags 0x1000000000000000, UUID ca259c26-69de-2116-277d-3316b605c746, Type 0x2db45fe, Active False
secdata:             Offset 0x0000000234040000, Length 0x0000000000006400, Flags 0x1000000000000000, UUID ef9bf688-bd50-f2a5-4b06-c062b014051b, Type 0x76cfc7ef, Active False
catefv:              Offset 0x0000000234047000, Length 0x0000000000080000, Flags 0x1000000000000000, UUID b310ce49-cf04-a92f-e4d4-48be564a1692, Type 0x80c23c26, Active False
catecontentfv:       Offset 0x00000002340c7000, Length 0x0000000000100000, Flags 0x1000000000000000, UUID 746c1571-49cc-0315-8870-2a3fc0026563, Type 0xe12d830b, Active False
uefivarstore:        Offset 0x00000002341c7000, Length 0x0000000000080000, Flags 0x1000000000000000, UUID daea24d5-4471-1a65-2976-52613350ff20, Type 0x165bd6bc, Active False
modemst1:            Offset 0x0000000238000000, Length 0x0000000000280000, Flags 0x0000000000000000, UUID eba35ae0-8801-45ef-2b78-653098e592a5, Type 0xebbeadaf, Active False
modemst2:            Offset 0x0000000238280000, Length 0x0000000000280000, Flags 0x0000000000000000, UUID 7b6f3cad-9334-f404-c57a-1ccd9a9e5b76, Type 0xa288b1f, Active False
fsg:                 Offset 0x000000023c000000, Length 0x0000000000280000, Flags 0x1000000000000000, UUID 076035a4-99ec-7269-292b-75b90cca21d7, Type 0x638ff8e2, Active False
fsc:                 Offset 0x0000000240000000, Length 0x0000000000020000, Flags 0x0000000000000000, UUID ac969037-4774-96a7-127e-ad9d45f43017, Type 0x57b90a16, Active False
onyxconfig:          Offset 0x0000000240020000, Length 0x0000000001800000, Flags 0x0000000000000000, UUID 86c346d4-3ba1-df1a-8466-77fb59991aaf, Type 0x97d7b011, Active False
userdata:            Offset 0x0000000241820000, Length 0x0000000c4d7dbe00, Flags 0x0000000000000000, UUID 62eb12b1-c980-e0d4-961d-0354f2198b6d, Type 0x1b81e7e6, Active False

Total disk size:0x0000000e8f000000, sectors:0x0000000007478000