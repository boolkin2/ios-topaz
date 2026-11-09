#!/usr/bin/env python3
"""Build the minimal Apple Device Tree for the SWEET xnu on MediaTek MT6983
(Tecno Phantom V Fold, AD10).

MediaTek variant of mkadt.py (the topaz/SM6225 reference builder); the
original is left untouched. Same early-boot contract:
  - patch 0016: SweetPlatformExpert matches root compatible 'xiaomi,sweet';
  - patch 0017: pe_fiq reads /arm-io/gic 'reg' (SOC_BASE-relative, exactly
    4 u64 cells) and 'virtual-timer-intid' (u32, must be a PPI 16..31).
Identity stays iPhone X (D22AP / iPhone10,3) because that is the userland
we run; only the hardware values (GIC, timer, DRAM window, CPU) change.

First-boot scope: 1 CPU, 384M payload window, no UFS node (root comes from
the mockfs/ramdisk patches 0021/0022/0024), no disp0/wlan/fbcon (display
later; early console goes through pmsg, not the ADT).

Usage:  mkadt_mtk.py OUT.adt [--dump]
"""
import hashlib, os, struct, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adt  # noqa: E402

# Kernel-managed RAM: the MT6983 payload window (first boot only).
PHYS_BASE = 0xa0000000
MEM_SIZE = 0x18000000  # 384M
# /arm-io children are relative to this; it must not be 0 (serial_init bails).
# Kept from mkadt.py; the ranges below still cover the MT6983 GIC (0x0c4xxxxx).
SOC_BASE = 0x01000000

# MT6983 GICv3: distributor 0x0C400000, redistributors 0x0C440000.
GICD, GICD_SIZE = 0x0c400000, 0x40000
GICR, GICR_SIZE = 0x0c440000, 0x200000
# MT6983 architected timer: 13 MHz; virtual timer PPI is INTID 27.
TIMEBASE = 13000000
VTIMER_INTID = 27
# Boot CPU MPIDR (Aff1:Aff0), NOT a logical ID. Confirmed on hardware by the
# shim's CPUI pmsg record: MPIDR_EL1 affinity 0x0, MIDR 0x410fd462 = Cortex-A510
# r0p2, ID_AA64MMFR0.TGran16=1 (16K granule supported -> no PSCI handoff needed).
BOOT_MPIDR = 0x0
SWEET_ECID = 0x544f50415a000001  # 'TOPAZ' + 1, synthetic (as in mkadt.py)

BOOT_MANIFEST_HASH = hashlib.sha384(b'topaz boot manifest').digest()

# The iOS userland is the iPhone X (iPhone10,3 / D22AP) IPSW. MobileGestalt
# derives product type, device class, home-button-less UI, artwork etc. from
# the root identity and /product of the real D22AP device tree. That tree is
# an Apple artifact (kept out of git): extract it from the IPSW with
#   tools/remotezip.py URL DeviceTree.d22ap.im4p DIR
#   ipsw img4 im4p extract DIR/Firmware/all_flash/DeviceTree.d22ap.im4p -o d22ap.adt
D22AP_ADT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../research/ipsw-x/d22ap.adt')


def d22ap_product(path=D22AP_ADT):
    """/product properties of the real D22AP tree, without the syscfg
    placeholders iBoot would fill in (flag bit set) and the node bookkeeping."""
    if not os.path.exists(path):
        print(f'warning: {path} missing, no /product node', file=sys.stderr)
        return None
    root, _ = adt.parse(open(path, 'rb').read())
    for c in root.children:
        if dict((k, v) for k, f, v in c.props).get('name') == b'product\0':
            return [(k, v) for k, f, v in c.props if not f and k not in ('name', 'AAPL,phandle')]
    raise SystemExit(f'{path}: no /product node')

u32 = lambda *v: struct.pack('<%dI' % len(v), *v)
u64 = lambda *v: struct.pack('<%dQ' % len(v), *v)
cstr = lambda s: s.encode() + b'\0'


def node(name, props=(), children=()):
    n = adt.Node()
    n.props = [('name', 0, cstr(name))] + [(k, 0, v) for k, v in props]
    n.children = list(children)
    return n


def build(seed=None):
    seed = seed if seed is not None else os.urandom(64)
    phandle = iter(range(1, 1000))
    ph = lambda: ('AAPL,phandle', u32(next(phandle)))

    chosen = node('chosen', [
        ph(),
        ('dram-base', u64(PHYS_BASE)),
        ('dram-size', u64(MEM_SIZE)),
        ('random-seed', seed),
        ('debug-enabled', u32(1)),
        ('firmware-version', cstr('mt6983-shim')),
        ('system-firmware-version', cstr('mt6983-shim')),
        # iBoot's SHA-384 of the boot manifest; /sbin/mount -P 1 exits unless
        # it exists. Fixed stand-in value (same as mkadt.py).
        ('boot-manifest-hash', BOOT_MANIFEST_HASH),
        # libimg4 (cryptexd) aborts "failed to get crypto algorithm" without
        # it; real A11+ device trees say sha2-384.
        ('crypto-hash-method', cstr('sha2-384')),
        # MobileGestalt's screen class: display-scale (u32). 1125x2436-class
        # iPhone X userland expects 3x; scale 0 makes SpringBoard's
        # FBSDisplayMode "infxinf@0x" invalid.
        ('display-scale', u32(3)),
        # XNU derives IOPlatformUUID (gethostuuid) from these on arm; without
        # them CFPreferences cannot use kCFPreferencesCurrentHost. Synthetic
        # ECID (not the phone's); chip-id of the A11 the iPhone X userland
        # expects.
        ('unique-chip-id', struct.pack('<Q', SWEET_ECID)),
        ('chip-id', u32(0x8015)),
        # Security status as on a dev-fused, undemoted board (tuple 0,0,1,1):
        # MobileGestalt reads these from /chosen, and mobileactivationd's
        # DeviceType then takes its native "Hactivation" branch.
        ('certificate-production-status', u32(0)),
        ('effective-production-status-ap', u32(0)),
        ('certificate-security-mode', u32(1)),
        ('effective-security-mode-sep', u32(1)),
    ], [node('memory-map', [ph()]),
        # Local boot policy (kern_csr.c): SIP relaxed like `csrutil disable`
        # (lp-sip0: untrusted kexts, unrestricted FS, task_for_pid, kernel
        # debugger, dtrace, nvram), lp-sip1: unauthenticated (unsealed) root.
        # The iOS shared cache is in no trust cache, so dyld can only map it
        # with CSR_ALLOW_UNRESTRICTED_FS (vm_unix.c shared region checks).
        node('asmb', [ph(), ('lp-sip0', u64(0x6f)), ('lp-sip1', u32(1))])])

    # MT6983 first boot: a single CPU node. Boot core confirmed by the shim:
    # Cortex-A510, MPIDR affinity 0x0, TGran16=1 (16K pages OK, no handoff).
    # No secondary CPUs until SMP bring-up exists. Topology properties are
    # descriptive (ml_parse_cpu_topology / createNubs assign the real IDs).
    # NOTE on compatible: 'qcom,kryo470' is listed FIRST because SweetCPU's
    # IONameMatch is 'qcom,kryo470' in the prebuilt topaz kernel (patch 0018);
    # our mt6983 branch changes that match to 'arm,cortex-a510'. Keeping both
    # strings makes this ADT work with either kernel build.
    cpu0 = node('cpu0', [
        ph(),
        ('device_type', cstr('cpu')),
        ('compatible', cstr('qcom,kryo470') + cstr('arm,cortex-a510') + cstr('ARM,v8')),
        ('reg', u32(BOOT_MPIDR)),  # actual MPIDR Aff1:Aff0, NOT logical ID
        ('cpu-id', u32(0)),
        ('cluster-id', u32(0)),
        ('cluster-type', u32(0)),  # homogeneous CLUSTER_TYPE_SMP, not AMP
        ('die-cluster-id', u32(0)),
        ('cluster-core-id', u32(0)),
        ('l2-cache-id', u32(0)),
        ('l3-cache-id', u32(0)),
        ('state', cstr('running')),
        ('timebase-frequency', u32(TIMEBASE)),
        ('peripheral-frequency', u32(TIMEBASE)),
        ('fixed-frequency', u32(TIMEBASE)),
    ])
    cpus = node('cpus', [ph(), ('#address-cells', u32(1)),
                         ('#size-cells', u32(0))], [cpu0])

    gic = node('gic', [
        ph(),
        ('compatible', cstr('arm,gic-v3')),
        ('interrupt-controller', b''),
        ('virtual-timer-intid', u32(VTIMER_INTID)),
        # pe_fiq (patch 0017) expects exactly 4 u64 cells, SOC_BASE-relative.
        ('reg', u64(GICD - SOC_BASE, GICD_SIZE, GICR - SOC_BASE, GICR_SIZE)),
    ])
    arm_io = node('arm-io', [
        ph(),
        ('device_type', cstr('sweet-io')),
        ('compatible', cstr('sweet-io') + cstr('arm-io')),
        ('#address-cells', u32(2)),
        ('#size-cells', u32(2)),
        ('ranges', u64(0, SOC_BASE, 0x100000000 - SOC_BASE)),
    ], [gic,
        # No hardware: watchdogd checks IODeviceTree:/arm-io/wdt for no-pmu and
        # otherwise crashes trying to set the PMU boot stage (customer builds
        # ignore the -wdt_no_pmu boot-arg).
        node('wdt', [ph(), ('no-pmu', u32(1))])])
    # No disp0/wlan for the first boot (display later; wifid stays unloaded
    # without a wlan node, which is fine here). No fbcon: the command-mode FB
    # is dead and the early console goes through pmsg outside the ADT.
    # No UFS node: root comes from the mockfs/ramdisk patches 0021/0022/0024;
    # the MediaTek UFS driver lands later.

    # pmap_compute_max_asids requires the node even when no overrides are set.
    # An absent pmap-max-asids property selects XNU's own MAX_ASIDS default.
    # No effaceable storage: keybagd then reads /private/var/keybags/systembag.kb
    # as a plain plist instead of decrypting it with the effaceable key.
    defaults = node('defaults', [ph(), ('no-effaceable-storage', u32(1))])

    # MobileGestalt HomeButtonType = IODeviceTree:/buttons home-button-type
    # (D22AP: 2, no Home button; absent = 0 = Home-button device).
    buttons = node('buttons', [
        ph(),
        ('button-names', cstr('volup') + cstr('voldown') + cstr('hold')),
        ('home-button-type', u32(2)),
        ('opposed-power-vol-buttons', u32(1)),
    ])

    product_props = d22ap_product()
    # Keep the mkadt.py sRGB override: with 'P3' MobileGestalt says
    # HasExtendedColorDisplay and WebKit renders into 10-bit surfaces this
    # kernel does not provide.
    if product_props:
        product_props = [(k, cstr('sRGB') if k == 'artwork-display-gamut' else v) for k, v in product_props]
    product = [node('product', [ph()] + product_props)] if product_props else []

    # Identity of the iPhone X whose userland runs here: compatible[0] is
    # hw.model/hw.target (D22AP), model is hw.machine/hw.product
    # (iPhone10,3). 'xiaomi,sweet' MUST stay (SweetPlatformExpert IONameMatch,
    # patch 0016). The original topaz/khaje strings are kept verbatim for
    # identity parity; mediatek,mt6983 marks the actual SoC.
    return node('device-tree', [
        ph(),
        ('compatible', cstr('D22AP') + cstr('iPhone10,3') + cstr('xiaomi,topaz') + cstr('xiaomi,sweet') + cstr('qcom,khaje') + cstr('mediatek,mt6983') + cstr('AppleARM')),
        ('model', cstr('iPhone10,3')),
        ('target-type', cstr('D22')),
        ('target-sub-type', cstr('D22AP')),
        ('manufacturer', cstr('Apple Inc.')),
        ('#address-cells', u32(2)),
        ('#size-cells', u32(2)),
    ], [chosen, defaults, cpus, arm_io, buttons] + product)


if __name__ == '__main__':
    root = build()
    blob = adt.serialize(root)
    open(sys.argv[1], 'wb').write(blob)
    if '--dump' in sys.argv:
        adt.dump(adt.parse(blob)[0])
    print(f'{sys.argv[1]}: {len(blob)} bytes', file=sys.stderr)