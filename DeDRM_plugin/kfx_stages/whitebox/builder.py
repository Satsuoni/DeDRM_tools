def builder_vectorA_pure(state256: list[int]) -> list[int]:
    a1 = [(state256[2 * i] & 0xFF) ** 2 & 0xFF for i in range(128)]
    a2 = [0] * 128
    for i in range(128):
        val = state256[2 * i + 1] & 0xFF
        prev = state256[2 * i] & 0xFF
        if i == 0:
            a2[i] = ((val << 1) | (val >> 2)) & 0xFF
        elif i % 3 == 2:
            a2[i] = (val * (prev + (state256[2 * i - 1] & 0xFF)) % 257) & 0xFF
        else:
            v = val - prev
            v_mod = v % 255
            if v < 0 and v_mod > 0:
                v_mod -= 255
            a2[i] = v_mod & 0xFF

    a3 = [(((a1[i] << 3) | (a2[i] >> 2)) + (a1[i] ^ a2[i]) + (i ^ 0x5F)) & 0xFF for i in range(128)]
    for i in range(1, 127):
        a3[i] = ((a3[i - 1] ^ a3[i]) + (i ^ 0x3D) + (a3[i + 1] << 1)) & 0xFF
    for i in range(126, 0, -1):
        a3[i] = ((a3[i] ^ a3[i + 1]) + (i ^ 0x7B) + (a3[i - 1] >> 1)) & 0xFF

    out = [0] * 60
    for i in range(60):
        acc1 = ((a3[(i + 7) & 0x7F] ^ a3[(i + 39) & 0x7F]) + (i ^ (a3[(i + 71) & 0x7F] << 2))) & 0xFF
        v1 = max(81, (a3[(i + 13) & 0x7F] & 0x3F) + acc1)
        w8 = (v1 + (a3[(i + 53) & 0x7F] ^ (i + 7)) + 81) & 0xFFFFFFFF
        v2 = ((-w8) if (w8 & 0x80000000) else w8) & 0xFF
        b32 = (v1 & 0xFF) if (acc1 & 7) > 2 else v2
        sh = i & 0x1F
        out[i] = (((b32 << sh) | (b32 >> (32 - sh))) & 0xFF) if sh else b32
    return out


__all__ = ["builder_vectorA_pure"]
