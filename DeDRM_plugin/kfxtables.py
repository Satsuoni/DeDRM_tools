"""kfxtables.py: the ten 4th generation sub-engine lookup tables, stored as a basis.

Import verifies the basis and the plane it builds and raises rather than hand out a table
that doesn't match -- a wrong table doesn't fail loudly, it derives a wrong key and reports
a decryption failure. The basis came out of this plugin's own raw tables and reproduces the
law's expected output byte for byte, and the engines match the raw tables this module
shipped before they were compressed.
"""

import base64
import hashlib
import struct

__all__ = [
    "d0x6a06ea70",
    "d0x6a072a70",
    "d0x6a073a70",
    "d0x6a0797c0",
    "d0x6a07d7c0",
    "d0x6a07e7c0",
    "d0x6a084498",
    "d0x6a088498",
    "d0x6a089498",
    "d0x6a08f170",
    "d0x6a093170",
    "d0x6a094170",
    "d0x6a099e48",
    "d0x6a09de48",
    "d0x6a09ee48",
    "d0x6a0a4b20",
    "d0x6a0a8b20",
    "d0x6a0a9b20",
    "d0x6a0af7f8",
    "d0x6a0b37f8",
    "d0x6a0b47f8",
    "d0x6a0ba4d0",
    "d0x6a0be4d0",
    "d0x6a0bf4d0",
    "d0x6a0c51a8",
    "d0x6a0c91a8",
    "d0x6a0ca1a8",
    "d0x6a0cfe80",
    "d0x6a0d3e80",
    "d0x6a0d4e80",
    "d0x6a0dab50",
]

# 368,640 B of raw tables: ten blocks of (4,096 x uint32 T_A, 4,096 x uint8 T_Y,
# 4,096 x uint32 T_B), little endian, in _ENGINE_ORDER order. Both pins below are
# sha256[:16] over the bytes described here.
_PLANE_LEN = 368640
_PLANE_SHA16 = "224110ddc06d69be"

# The 12,000 B affine basis: 1,200 B per engine, in _ENGINE_ORDER order; sixteen T_A,
# sixteen T_Y and sixteen T_B records per engine.
_BASIS_LEN = 12000
_BASIS_SHA16 = "687553ca8ef8f628"

# The engines in basis order. The public names below pick their tables out of this build.
_ENGINE_ORDER = (
    9708,
    1031,
    2069,
    9041,
    3646,
    6052,
    9479,
    9888,
    4648,
    5683,
)

# The nibble-XOR block the matrix repeats: ((x & 0xff) >> 4) ^ (x & 0x0f) for x in 0..255.
_MATRIX_ROWS = 96

_AES_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

_BASIS_B85 = (
    "6173MC%mO_kd!}9A4xnP%v=kPNrUj}Z>FdD(-DQ-1tW^*slbp>r9B|$@kHZRqfb{s+N8?DWUeDdEtmRcN{$uK2@=1eT@q{H0"
    "DHq)dr8ALkT<Q71Pr)Ps)U<+bx{30q*IMSyNIc@8`mfFTWchlD%@faoq&iR4rkr6=#MQcGwlt{Xf0U?HVm05ZYuAnAATYZ*S"
    "1L&Lb}E*KEzglU-w`2w$og8>5IG=xJ~cXX`bK(<{Wkj9N~^tQ%Uv!F%?hIb{>&tdbtsZH>TD8D53^Dj$x>kN5=a6^Iq$q0C?"
    "6Tk^6<~#z6!P8*!WBe6GE|(Z`iQ6tL3TMR4N5g5g3zJKpQnOf(wza=7UY>(Vi$EOaJ;Fl<lXb$JCUXVcKi+Rv*0O()CWu5^T"
    "t3j)a~j@SCzBA{O_UwkxLvct-kiybkUSMr}_#A|bje!AK)Mfd!h!LZ91OS5S(Y_IJhblAu;O^zy6?ikrD>wct}xfd$NTB$eL"
    "2@}L%TF7*P3Y~`02|fE5WhgK#<~tT9so_&djmvXg6jN5PulxC*{I=EnATrA9h?9~XyQ9!XFeYuRUv7J)J7eAciot>nuURM@n"
    "^F=D9E>oRs#gfK7ku5hN+!)ckV~EV-oWe}{^DSttu+9Mfh$9|$&X*5%B%a*dsk?HOoWL1xnd15b17mTaDU%;4w?C?rF8)W@J"
    "0ERag(VaD7k#WlidW?q}6^2Jhfz`;P2G}JAw0Gq^bc2%tgpxKe%jSK|05JGgX-eTawQm>PX?EWYu&cV+!7&)8~MdHIem4wNY"
    "_}+o2Av;58;3p_Ov>hT77VaWVNVdV%Z^@q?*7qCUGnt(Z6TtW&8lDJG+~5f87X*|4QV6v#{3X<^^P<v2)~h2WYz6OTTG2dkR"
    "ogKf?NIl^cwKRf9vPT{@qvbS8gj2KG6%{k|mvVrESJgCOoO*tNb%`P;C(ra*6o8lBQOdrUIoc6Obqp?U0gicyCNrI!Z+9=Q^"
    "FfnwNFI4tH3fp+Yh0*K8e_xWAAQe&qdA#6N(Enp{Pyd=FG5I7SY)E|=zim>m8T>^1e5(}9+=6+jsGr$VY*XlT&vZI=H#}<ku"
    "-}rh-T(|`FQT`g^by>m<?a@p6i*d%s$QO;9GbN#pIv`dzqkW{E*DJgefcsxvM|&N8AIy|i2tR-9`}H<MFnIsMsQE3p#?mUx#"
    "~-kUk{TFAA;OjE}5|9!g2we2$%mDk6^*ma(-yP${w(cgK;|&v3fe^9j24C!jQ8_x~sGnE=B(rHPh*w*qpv$i9v(69oEmAd=M"
    "5E4gAG&CC-27GhR>4*<SNh+y|=>MrtJcx~!?8ffiUcY+|d1d&cSc$2&(;9WWi;dY9g`f``m>3R@*x_oYezxx!B<?UdkZ5Gvk"
    "sq8s(0=_#-_lR&Cxd_F!xDbHj}LsS$LZ-ZA$A(|L~P%n1?HDQ{DB3035ey%2dR4C}&^o4V?nWFV_1p3iYW(pfJ-|$1u$43=K"
    "yB0u?rO&G3P;*PxWOlT|iCa61vLj=<2VI>G;F*BHY?ONNTrW-B51b#0WeoNK{KAJW?T7JhoIBzWVnx3tvF!01m=egKdb=_~c"
    "2u%2(-<FtEB9V)4!Br#w{Xa~`dE-O4d>_m%)iWaq~ty%pRKmT-Xp!_+Fjt&2HN8|QrUuB^Jf$T>UtG7Z&YU$QS^}Lt={RV4V"
    "lBY0*>W_Bq<ZGg@w@$U~Rg;vtS@tJKdKVg6Xh?R%d046uOCu9HDsAU3Y`Y55r|>23<raO|6=$-lAVE#{Ou`DG&2kG;EZn7Um"
    "e+?LC8lmfOq!nhBL?mv=@?81>wLMB%S;_jtM0C)oEIhJL}kbh&;A$%3EKZ*crFuZM-QUvl+sWNG?`dX(<Yi1&E6q!)hn9L&&"
    "pnjq2Lp-I-EO?}Wdhh^P52azY3C31dQbIwH~O~vemQ3Wb;LEbzLP2Ft=yl@a_ZSO9X`H}}@F|}5C(O^;~eKoSM5{ss|eJZVl"
    "q=z5;aBe9^bGzN`H{C{jk2rv;1^k#urYeQ$MBxMOGN;{bcyr~G8uy?#ni6CN_C=>xE0munSh6X>1wBG1G<M?IA9tXX2^Y2TQ"
    "f@6!#MPeC3Fp?^06oK#j=#o)7>qt>%EAK(B`xQc{W$@kW_8LLc~@vJmf!W?ST%GwKM+j@us^p>Ex2^HbUDdY&N^>3%$j>(5_"
    "jMXWrNG!RVF4=(}l0f(~P)_nTPD@ii42LD>u2CiEAyqvGZ|L?%*Rl)P@y)&j+*pe2aI9`35{8dH<dIW9Xxxkz(zJ*sAzLpiO"
    "I!jAG@vl}03%7er29?<L#3{RRKlFu8tCK#gf0bxK`Xs>A0y=_r&0Ps29$Zo2CF^x+YKH`zntxKgj3&pj6h6NRIS-AOaB*UMG"
    "4A8tcAiN^m^WOx3#L~M}dF)WZ#a0QN4c1bl<B>&ZUTpYD-<C_o?Mc88wnl#{IOu_)#1Sz2IqLs8jrWBms%P(4h#Fhr;*&nh+"
    "mVxeTH#wQU^kS)ezjGMH{?29_X<5eSs^r_-{XxDq?q6&Nt|eN*xVbtTmx}i8N(Tsu`1X@IP!3%VsUcLj?#bmt-R}G=PLf#ID"
    "u=R&40yjBA(UpgghHnW4BB7#!bj75fJ><9MhiQWvX?N{XLBg=uN<fvYlLch$b89E8d=yf2t;#HwrIJ`jnKGdJe%kyc7#R}EB"
    "O|k{OTdL>5aljyMCWsrO`hbOdfys%wR~tm}Llp{cEvg=#uWYj)zXweCX7X_T=%74lQSno%$Yn&l~H%&S3B1t{3+6Ko*e)MCx"
    "czFmb1FEnc7cP|T7mscOTSZezi2z2nmstJoUdD|b!*!|m~>xNm)|1{pNnHm(uI54jNHdy!mch^@i>?;iH`6Y9gq)WH5Amt?3"
    "3o%mi&1)Ct8cFmGA2E;MizAD2gn3U#?ZyY?=SV^h!f9FTtQ72nO9e{RXXd9h^5b3D?`=y-b<gw@s`O^~;v!T7^)+|ewpsFJ&"
    "?o+<K50?DW4V%K1B?$j^N_+_oy)xW}gX$GH8P4j2Gpp-kLU-I#Az+8MTspw7r_EK<X?lae%NJhFB~FGs%qK@UFw0AR(<k9`W"
    "GJ}<lp>8nWE6~;Hpq?zyamHc-Ms<(8AqS^`22kv19}~wXG|do2VIt`aalR2HuFIvXx^+Q`K<m61kf>zhgS(t#dJRz_g=~Rnp"
    "$NdnVR->3W<jjrmgyCKd<@o99*0)nyfvgTKi*RE0KjzqDoTvIO^borANX1x}yUvnJN<Pr+Qy02A#sFAv20p4A+z^T6F%Zw?`"
    "a`n{2@z7I-25lL0WrLkpdq+gD!upa*SK55IxK6=8Dz_mioCq<lW~k_{D|U&F=ovY%SO2Zjr~kgdwU`#>~2N(nser(=q1(_kW"
    "%qKj|eCrJmUnFbvI#zv!S`wPdLv+~i(cuXfnFoe*iMH*>FWq6fDHMtSN#zv|-E-&w3Q@m~&PKwIUh7-|~^{c5kJVoNh_7!zi"
    "aYOcUTJnJ9(BvS;O(67vMX%ak<-D1ipo6~?*97<%i;9Ku7||o6<!ry(Sg1C9PI;>kx)ACS{N~)mOacKo!a#wB(x9E0nWl`Rt"
    "i}DGQb|9IwoiK}wVe?7f6B;kRG1mUim$|@Q%1<43rNK9*wa}N6LNWqB+X&;oY=nX1;JlMVRD#<JR6(hf=98DeZ6$|w;@L|*5"
    "-1mV*<%+6J}SMO4VJQ<rR+jP1@|1Jdy9P*d&7M-=|vZP7hCs*%z`xj&HFasEXclD5g=O4l)n+HR22d?V1ax+83XsO7-9-0{y"
    "OWe$Nhkt;~$yMYRs-7tNp2F65zsIQ)Be(Hl;|a5z_96haGhQ@0K>R>oq96lgoSM*`Jxmn5+4QmY`~X^Qhngz`jB&kUBrx4Lu"
    "xzEK^p{;tLRn>|P@7EzXIn(3qWk2}BwN6$M&ni16;_fvcGr}c%(9w@96MuIXTgX?|UOj@8$!$b~<%Cy8^a5o4T>-Z7m`@e16"
    "tfs|kYy6(Eu+62XUiV1T|3qTiu|W|Q7^uBDYU=B~@c=KJQ#ab^{)o+G$<g=`;w^vIg}NF>8gLkfj8+uIw@)^}ZacMtOx$V@T"
    "1_F@0gZG#T|G$EWu|8}TTWM_lk(w*c`%gmc}vlw)DoGOc-%z|a=N_&_tF)h`*A&<I7)s6_!#C%LCPM2EvM4^+<zgQchX}qh|"
    "fEE6Vv+BYRdD20r8-Xse-cUf6chH<vhW|Lo@VH=Jqgv3~9;pz17zraxX;8!%v-Bu<r(c)o+WbQz5DB(NLIei{zQUqGPIq+wz"
    "(sg89KCcvw1DP>gKGWCcw(Cn|bC#~}l7I`&fVi|01g57=><Xu5D&!k>jd&UGo{`L<}r=E{cCpDh8m6)>?1i!!R#aV|0k<C!X"
    "8%ICi{CV7@{wWzs+%(m*}H9rW9Zq`wKeG@<5)+UWk26ezw&*=nr*g;7d#WP_q%eS3?cN(k|)8>hUF~Q9vkLQa+&*FKTK5e(k"
    "?tT17>E-uP)4}Bd&elm%CcfQP8LY8mm)!EBH9JQR(vvy`PZ-ogJcyQ}>lZEsTe{XioP819$2Y!~Oe*nz8eSuo^-qfGYd=VI{"
    "$z|c#NjR^0Yg#Q!z7l@k4*-iDwhxr0TZ~|>Gw?-J?RY_c30Knqk-3;^ne6?tL=@(=8t(yi4QA%L}AJ6fX{8pJRZEdu&|8ZM9"
    "TU~mR-xvjx=`@(&$H2<0d!zL!7FFd)1#{iYJFtfz!FSeG*r*;`nBk?goJ@S$sEuYGg%AhYbzSt6hIJCiNO_?;XDdbt}V&S8L"
    "K^WbNNhzjkWri$YC@a^J&fbBjh^=X%&Br}(qY3m}<<NmIci6R-}mE+NygVC5pi7?J@vO45_WJnFp)O$Km9A(I!{!yQuqL<{&"
    "Wm~8mHj2_me2NSqno8T!bp|d5AtiwQB9ov8M0DZOxT>Dqz16>lm>0=1B4pKQ|(vw)|J44)#Dv_Z=u0HhmQ#hcsWghv+;wuU`"
    "UY=o>u6#qHCYADM^q@ZJCRS=RWgr;0eoYnPN|AwOr6l3;kyIImK^2&#)hGoly3r49W&7n4j|>42`H7aA<a=yDpEQJA%scs32"
    "E3A#!hnBqa_;xR;v;BCk*$KI0qF|`h{9eRxWW-8CRIHNA3X7SCpDfAQ>}%s+qSAmgXf@VqM&>$O;OGQ_#<!>7xo<w?0nk`1s"
    "Q7LMCbpjfLgZmt+ltUln?V4z)r&M^DOVjSBoN#0w+cOcHSEY-{_{52^tRbke6^pt9^g#vxO*Vlpj_cDV^0`u%MC7AHGIZnKj"
    "{Bjmp8OT_w|*R3LhM_+q>EI+4F#wulEz>E4HQu@JS8QPA^#b9~aV$zduEf_LAgUO_3eS<Pz&#ly3GFNpzLUj7JBBrwpoi4%<"
    "`VB-U=g<AUZX*@y8mD~iy=ZiI+W}`9-c^SEa2;^8id_Yw=lmc{fj<l3aGK^02!^lCe84!+x(Y)!LyWQ{HXRVpCHzQ;)|Kgw{"
    "sQJ0RZGZiZ+*=vBl^qQLz%f=mlobfGBAF3wS<mGgQ0-KOz7)EJBLnDn+3t3e@jD8wPo2h0V}r)Ku42kT%M)$Jl`6@fLDIVTX"
    "|cuoBM>uABl=bO4TFBPs?g(!)?icF?UYvp+5K5V3@Sw)%S2Bd<r+ezXeGaB^H}U$q20|&-uu@_pizplL;jvP(>B_;dS(9F(k"
    "=H=xqTyb0AF<C!Hm5@qvpdN5>VXZVrw>CCb*przzSYPW#f%G@1|;jnE5sl?plx2kV)eu0gF&CEP#%PCc21cyA%waNwBPXB=0"
    "t$4(1|VsJQ0w=0H9I;$_(OW7^qJ%E(0Pzw&;sVeE<$JL>kd%=81rUl-nf<8}4!9;_In>rmO?4-SNsCeg{R#vmH#BaVWgyq{M"
    "aqUo2p_6rQM_+mWM_mldY?Ur&|;pW5Kf_x|LLR{6;L;xrm3ohlHSg83c!0l6ur$`DR+SjZjY(RlLrW?<U_2~ask|Sa4*~4td"
    "{p|fg7WMG#akbuFxVbxNeXdd@4cg>&(*$H1%MxNN#e}(K@VlKw8_5e#s)wi{DT%{~f{CZ)FKWn&-3?5odBva^wsEPjE#h2R6"
    "^>zl^_xtiWUh?ebASoiQh-G8(lZ(w23!t+8r+LlLPPQ}dc=O{{`Bc+7|`a&YMwhXr0;5YQm@0ULU~c;@^tvB)~s25J_7oR%7"
    "%Q(+yJY6HrBM-Z=A_U!c16a^piljHR8<`H8bd53=y+2W#60e4d+-gIW3kbK`{2G45?h#{9xssZ9!<}pX#u`=-uWxr(>U`MGO"
    "-h=}kj!<_S(0ds7*42V8GO6GE&BeuDjQxy^PhX)wqdsYzM7C$JV#>pU+;<J%;wnSO`r4LWYGR-n-?DdUfVZt4A%H1HIBEXm{"
    "z?NP`^d-zo<f#BchSQ*tYM`bo(tTjU0+`;LG8jokqqkQ%rgSkc3j{(=x(E5$VSnFE%RpzrRj#hG=a+YhRZf^?>N|1HL|A-Qo"
    "VGFh>dDQde#C{}Zrye)3N-oXS<b#Xu`I2VU8XP*kw=47Pt=6$y?FPBF@Chl`1d6NA@40n68HsZD79o{jQ?ZFD7H;S`87->H1"
    "-UlqRIHLWLaB7XoOx$F0&Ap!mr;|h_Qwqc|H{Ao<x<6`QC5&aoUM3Z^bKij9z#mc<H^A98$5Rh-M~64uFC&8CtSsZkz!9|o>"
    "RbDU@i(@sYFU|4lzw(-qkbH^YobAm2Z$mE#SFIO$0DI^PrmI0SgbG9}B+eEFFCi0qM*}i}B&-B)~7KNnMs~R*dUoXg6VOTt9"
    "@)?H_DA#t_MvNb&`L{mtyHXx{z2Al+XD{_7$iFhR=>y3TsLvtJ1}j<PY{=-DJ)$U5VSNPZ!Nz<#Z6o72rcPG8@w+T5MnNzgX"
    "4fU4`Oxq?mj5yBvOyvLM@3+#ih=#ryjmm^MnwRq(%niFy|IP(gAJ;M`Q$ydv&cXSZ@P|Y7$;Ed}5&$uS$BlD)nia#*W+`b{J"
    "|KW6%K<p94;>k%6b%(e1;6>P$)N~&w{B`Xc0WoWjtR_aeC;lN5@P^@Egr5mgMVtKx0SnUD<aD9kEaEWqv|dxr%N!GJizf{1o"
    "=?-y|MtEee`5uJP?G)4h63k=2gP{5*OxIb%8K^xjOA7Va@ohF0sF<GUyG1Ez)ejsE6>PXL5LISQ39a&E(wI8)Lfc%Ar5Uv^9"
    "=LSnUxZc5U1Z*#n#y)uo5E0YULy{!5V!ItOk?zFX4&Z5;^MW+v10dvW1o4&>3H-Zxxtjv(S5*-zi^Gs9dx*fU4<$y$!NMP?g"
    "56y0a*}(s1p^bbh}H1Fh|n*Pyu49=%Guso|$jfZZa_y2&G2{STY;>jK_RF{{Ae1V^i~oRaAZ`-#wi)o9G_CwtUotj7!k6!9{"
    "hlnV+{(Q)Q}i)$K#sbI~Q+0c-5w=T@CU_g+VIsDd>sC6Fkr`yF{_P)9Z1YxW_2X8yXU6eUa<YL(WGFT5Q3@VgD*5fhW*bYi>"
    "7^;wi-Vm)li-&b{P5v-{g}26Q+1%s;#@K+h;N}d3fpYMl)jXPqb`0OjNt#|Gf^SG-gicIVw&Zhirv|${OiI$LBJs}F&Vrn56"
    "h5t?y$>2~dxdV1?BRii%dW~5`WSEx7+n^M2?=3v5Gtzg2an;~PqX=A*A)b)<!UOtm?L(@<clf*B*$*!+Ld&g!QhC5t2K7-K$"
    "N2}x+q5Hl(qV9#)RT?hEKe`Zjj;OtA>(#wxxe^fu;_Hb!WX$=Wm;`*+ho5{r4-X*i1a}sztzuY%eS7U(a{p#%^r7d8djq<vn"
    "(bYz^R_$cv0dVdtgZX*{R-j0G*wbLlh43Se58!Rv`BWVy>66-<Q=MJw=JG~-tPCt(Ujo!HQOKl#G<#xLF50q<5z1>HG-ivh#"
    "ye9CBf@)cfJphH$w_d!&#t(ok2?8dLBq1yJ@NN4H`yP=lFMvAf4i~Sl5ruKBwjI#oBv{!S7jt?v>QtA5APVv|PIS?s0IFR6Z"
    "WKO~pC8B41$!}q7ijrgIURlXrNVwP0r@|?$U?uMkC9w8rtC`9KYD+c%_X)oBx3k?|Y{%?eno9rlA^9R4Ie(R^pn5Hvq6+@?T"
    "kTSr=#UW%R{wm7Llu{s$MNR>!hK&bxL9!#+ROE{YO$~f-SB8vlPsevlw>dW<V#AjKm<mUCBUB-9X%8&W%0M1;gOyxOoE^88W"
    "wQuu^R~6e0MRnLXY&d#DekI&8bQ1Ou61n2~=p29V_bA(7(JnWzkS57NDe)hb3Uui++`^_!GJycT91#Ek+aYen<r02m_Z1*%4"
    "^deUevmbs=#L090<MebcEkB}3QO`bq|IhoC7izCdfOCf8X4LQdF1aZ7_UsGQArA;oi@X*PfH#B;Ez)$@jT88F!uIuK304gJR"
    "EfMw_=7l`1-mauQJyqQCk&XzSXRzlvd{_T*eQXUA(TK`j_ey26U9SCKiL<E&m``LH43>iF18F*U6|5@96$W1^aJLc&M7niEp"
    "+9&FtE_=vIHY)Vf`X$h-kz6EHdTksne$+|p%ROQKO-hi_q%1wbvuS~-T2p)8xrQfea#v)qJjW}G)PconUvp(()N(bX83UNo_"
    "X@{7PW{$5vEK7ezK2YGUZibXs3dCOxxt^*f|rC(A}hdD_LJvNH{;IFNe4!_O%-~OCI&J1!qP@nc#l&uIIgmeW<q}zpkhAtiA"
    "J$G-KiYuSlBmq$NkIIXFekp5!&P@(bJnw*IT2_%!G2BzqV8>_+JuO3(SlHgf34R7yIcK&6LPLFynO5=rH+XrBOU1<SB_RpSX"
    "x9#OG?sc|tIlDolC%#*+b6nW|0LYYs#;zJg%%iB6?1y<)eFa(y_EnwlC6xVc=z>6hP?9xIFLM<m@%5S2}n5!VAy*ZK%Ri6h!"
    "&c_vR|DGnY&;zxYAij>kSl4JSye#PQcEW^cDqP=<|M++2OqeCEK)UPff=SF^xB<BUNn8%Qt9*Ec1tYuqGUfaTiqY$p^=_Et+"
    "U%<}X?tU%K<9>nYA54?U;$d@)HDC4f7O=OONmrZ@m1SW^iLa`MpQz)mGT$D@{po&o9I^y34@qmk50gBv#Ll`3$5ixc55wshK"
    "hlI@=uh=lqBNYP9Frf(cr&r!iUP~uvuZ@^`5JXcut^BTMfE|5T?6&CbY3Du6H6GWDFKhYQY8X+E(qi4X5gZYGEJ-WTi4d$GD"
    "Nr05fCEOCA?GYB6xob1@yo;O=qA<ULql6v&k=_3>&Datma?(RyXD7ZQf~Hd#ax>$oziN++flA%T)A{-XaNOW$RhZ_VnO<jDG"
    "}f%5v^;UO^Vz2bzO7VGB8a0u13*t@c!4rDbqDWefq#;VST>HIR!6Aj08qP`{!FmF}*<PP$8|^(YakGabh>;SD#whs{WN{2p#"
    "z?nph@X({zwnJLc(X?a7Fex7U(bxrLgex*lNYDpLh5@QCH?+ok5{PC-@nn(XzkdkOf77HQTIXTAkLXI<28p?uWVmfrRqH$XU"
    "gz#c=@9jCjs+xeSq;A=HCx=b;KiulfII4MS17J13uCxdJ)}~p~9phB&jK<P3G3+$6%*h31WdW;2*09Z1VaM6R+zxE9+j}I32"
    "u4)Z+Pas+mn~4yrpWMLxn4ZVk9u)0Mf!y;h}~TGo$euA8@t9Q!=Zm0Z+z(v0Lt&-0f_9LD&3Ta-NdVA{|i9QTDLv&9|PiLw7"
    "15p$2o522Cs5^KPDK!!~}!b5JERqenr26)a{}ZlVPQr^{Lh7s0h88-bA|Y+*pip7YBlqUfgEDJRucBh$>gX%jxM~Pl(Fw@ST"
    "4pVsI5^O&k$|37M6~-Nv0fFT84jwOyjqlJNi<dS-|K$*hQ7C5$~?sw#!ZELhd!4KAADN1`4Vu#cWRGFNdVyH-z)*-rz9vO8R"
    "t22SoljyE6bVX$1s?4#Hhx+pqe2x-{~CMAYYh8aaxb-=n+^_mQ}UyNSKi0I>RS5%$gX+`+J=;Y&7#s!uGG<m=SIrO^jb|+E("
    "?8cpVX&H7pY@?K%(?Wi*EHZ?_PlJ^H8|DWIK^Ek^Kjw|{JuOOmsk)m0XCbF{!k*QffqnXeZQ%LKJkxGsH0fg?jY;f;aXKI$x"
    "2#SrKfE>f!QlDgibyfVqQ9ny$p<pUuj1PCa=0RhJIoL0coYWfbtIv(F8ISlXEl4>28<>fXo_35`}6mmY=~EXq$iwWa#aQ*h-"
    "|1^M>PKL5PRjcGRb!QQ&r&IZ0VO{dTVO3l?bP>#jeZpzP3RZ%CSrV!Ijfr>E<2ZJG|}ni64F{nG;H+^#kg;g4V!j{XfouFS$"
    "_l!OAc;G|U}yEWam&V14AD`*B4{5{C+I-s!7(JNl4R9-PQ}Ue>-@nkc61Fbkprh~!nup+3DVOjbShFJqaEsw&#j#~#~Gywz&"
    "?_uYhQ;2gMP454|mfBfMEeE)5e)a(WT1cr~o&U0$rGn2FzE*_?cNay`}eT?$abO6U*p!87@PsEZQAaz)Go^yZ@_;plT2fPjJ"
    "FSI28_&8EO6`kj>k7@5`+B#r`zAQN?JL85I+)^_O&iQESdEOCuEXr)Ot$9FpMNxCSe@s$~S}_l@+D>mY7lMhX|GUFAH3fRgw"
    "}|d15hU-9jOA?ScM>$&9YIdxIHF`?oWLzie&eCzmQR>rEa13xg`EBODF3{IlKT_f$0#j-dWznnzc*{4E8^M-mTh~QrEDmpD$"
    "?&6q?OmkWb6B3Vz{d(zP}e10_B*y^F<l|jNg%fSC}59ZglwEK#Z}EBoHmuh_4k!KFw_zVc5~&a9huAk?UhQKe+D9dl<!ArIw"
    "k?i{$nyB5R%$6PmW*s4P;EQhRJT^8?|`hB~dA&JN%DxMMMCK?U(y&rH;5c*w}yv2+zrdUYROwFMA~K$pn05~DE+Nla%onCsl"
    "y#Tkpo<WYs{oa$XJ0aD-=j_N@(s@zKBq@&{XOcvmG7QyoCj$^c>X0tlJkm&rKE8WBp<L71MF|xBWY|1e3@@|diw@S<fOWJe{"
    "`t#Yp`9OJwb;5-Ljbz@1scpLZk}ahDRn*}rTd=E1y(nNePU>=1;^6G=?8P<vW%L*#8h5vJDRTwGvp8U|qRc0Gunkhm#%TJ;%"
    "|B<YL65Ti?pUO9)|mH!nsxx6dEs#h06;Y&yU7D1_a#Y7QH<4nv|U2>n;h9=aqWKFl|VeAA-w*8OYs~1L`3mi!(WQ=ZTI5Q_y"
    "&y*YReU_Y_~a3Gnwkty@NJ#k=($leXDT}E$F5hmc$HE8<E{3^DBs@*c#T|bX8)PYT@^}7$^8)l^&V)m+DuDn7(;H^Cu|u@)P"
    "D&CaY!djK{_Gy3ChnnMKrMijj0$e4)Fj$IOVs?X}ydL!Ol{qrSYsw;C#_9Q%@W%xRR@o7BQ~N-w5FNAzNE2WpcfS2>SJr@5E"
    "$JhJ3ApOqE``;f8um0t?VX%O!1DND+`uSp33Bse3<{O~x>3MIVzI`+OXI(skcO=j={lJtJqKYY^g>QU$&PS@%5tXgsemUAE*"
    "X(Z8CcGE+p-^m*-w<%KX+Te&2@s)kAi?$W*)%g0`L8LWwCN~6#y9~z%LDMDT-vZp``!b3OfQnJdHKY}Ak{OhxfTyKHxYMEvH"
    "PwoezA=cYbx6R3>7|2_;uO}ho6P!UDm_s?$ouUf99Nb4?3jl0j7J5hmw(f*#%=1(Una@c2voqTxgs){smB<J9-_>AGEu9SI-"
    "Mfxaizr#f)rd~#6fnM54-I9h{j1847C=OEnexVb!o8enC__f)3wHuHV1q}D!w48fv}pK=;WT5Afp(fgOB}n<2eWB+k0K>Eg#"
    "9-h9W_)ll_S~5(%6yY1mZkf4u0>sU%6;@CfxpApIh$X3??fnKa}tgzb(*O+jV|oCJ&}atR<_Z@wytdU%x2ja;`0Fh8`xAyl2"
    "i0^7$uL8ZAT9jt<dJFbgZi<>M;{av}fk&WMiVWYOa1+~B{`VyRF?@%_kg~gocJ1GWY{~=+ks&5PfT0M^l8+jD9VNh-7g9MM!"
    "WwE5cy`I}}-KqM=jMdQK!(JTmJ)b|dpjDXD7XnL`UYV|iobJvcxuL^q7SrA0LWA&MTA`i>r!I;b{I`i{r&oOSpw1IsRROnzp"
    "$8u7d$-DXHIzpUYluxW?cD}#Pc`9bB|r77M^mG85#(TAlSHPM);N&mK=%atQ-{JfZCV5-@2(SlYa{RK0|zSAQ6F^lX)jn%c9"
    "VcnY_qW*HIY~!MSB_pO3Iu}Rb?B3Lr=-5EAieCNc$#M5`-yH;)g`0N{|?owH}QV?Q)b}{HX`4TD&ELqI{LSdVBqVQ5YpQvLS"
    "bq!gU)yCbW=ugku!C*w<GYT010|@D9yH>N&?zWDdsCTQnt4a30zQ9_GE5%}j-|t0}{C=}^1skULH4>shSu9-GvUWNBe}l50n"
    "%v&1ZHAjh2OARzK2j7Yj=Sey6qqUw8;ThY$k)*MP#5284bBCvJ`DM~b{NvMc@E*=#yOmn#{`l;SM#0ql?{B{72`y@Pjw+>3v"
    "$7+;5Za&d+sF!Th9sBlSz96C-22U@vIjV8UT{otF{%%oXC>?w1CkG+M`1^#jcok0;8nr!+0`_{Y5R8_l9(U8M$-SuL+Mdi6M"
    "w3(;V(g^3(QwawwpvPJgDx!bjSde53&q}bxKMWqU)y}deZo5P<RiPLt*c}^RNf#&?Wg|6Z1<iOJNE)vIulCQb<kAFy|b;tr`"
    "gYB$a$LwT1jeRx9%G$Y$WMcHvVt40$SEJ$pc}kdutz)ZanWZQB4@sWh;xGGW!vk@>7kGIkAknZH8+A3+;dk-`fRH$!MaOR~F"
    "hSjS%$vPWq@MSNUy_b+F{choBA$Gp>YvVd)ceVi|^ZA9hZQlZk<X$3VeZiT;!Wx7ay&)&iczRzcxSvWhA|Au+F@+^@urdsdW"
    "3^mMGE_BZsKC^a)kabN?wiHQc?h-hl&%*Pu$YbaxQ+`<2JK>cB1!4Cx)4M3RgQ=G;m+$@EfPBV)w^Mb#T4)B?@c4*Ud^mfx%"
    "B}K%e#a{Y4J|!^Fe_b#<%$_W~mZLs0zDYTH@3Mbw9dqwABhO=uyzo(W4<4-*qc-K&vW`M1ia8m$wu5dqiC;X8R)ipLt@jEAt"
    "Y|x$tt`}IU!Tr9TBlek#2w82Np*|YxJzILr1*V%{oLE$_Ja=I%%=w}G}7JRz_+8!1ED(dn5^Ph=%zc;BV$8fOaU`q3F+JXB@"
    "u~DSce5>onF!e_31vVYt+?!^WrSJH+LPTbK$fKA#LaG>lWh`&5y*RopINKy0>$N&thBH%R-ko+N4eUA<YxIS^LilQ*sRWOc="
    "4+R<CE0(smKAWh)-sCIK%>w;@!hpyBdif0=97qN<^AUJYk&wFV${CBO9}oL$G|?%NPyL^=yQ+>qWszoAIKddyevnihfo=mPz"
    "1<AFWAtEbSLffv!8y`6rQhGYf&N^5W)friM;6V=0?<Z;>Gz?iKo#(}Zx!?k*YS}Pf$V?P<sTX=N$OTmA7<W?Yw61<#i?ya6Y"
    "iXPokv|3%EfeW!u!UTE6;AN=Dq&g<5%jh=_HzF#<NHjd>Z>4w>Cgs?bm`6z}Ks~PJmWHV-LLFDg>(460hWrqmF!I_iVj@TdC"
    "E@v}$bt<KgOeECS(QoX5GB7NRYX5uP3k6gbpFYOp^Q9Bqu(Q<j9yMp{oC|Z_o34d>l5)Yj`C`Nw4Hv^1chSl$Eix`%Fs6R8{"
    "1VS`?4W%SBLVkVXRO_>m|{zy}Y=MufnXT*0;?qTRCt9(WBLpHzX%Im`J+p6n;bcBhTi|4-@0U2m4v3SjtGS#@t2mM24(Tro)"
    "fxxJ!QnZ{q%^1v1sS>EQZrxvL+jFqZf~khm%w5T?bZs(D9>Y9%Dy36&x<^GId`jU5Y9ta+BQA@j+n?MBum%M{eCA2k$)GU+!"
    "&uz+~%AvtXiMi?LvT;1Ajf7-6es{GeK@^K%oF5?#Wojtgx!Iv7_^X#a!Ga}KEajnDD32$N?sXENHZHQ7EBp$^}n)`8x*iv-O"
    "85c|AxZx9SF$Sn-vJ15xFIKNbDpgzrbmx$v+)`0snBj_7okx39$V*&(^U$k_fM4?!!^X1yKPCD$LEU3`c#%!ZB;=1lVnjxda"
    "9Wzs1T}ALrl&=aA@y*sERivCrpgPzhXK?p&F>oV&M*AC(X@|z#pn}o(hnh;V-{boxjlg?<OP?#F3#6}F&dW7vg)x|GJS36J*"
    ")w=HQ*A%AagMS{&<!3y4eK$OmoiDW2WS;vY%aQ%&aZ8+a|ngyWsrLKU_RhC1kC;A^H);pa1h+U%>|)CePF9xhWK}<Crj>s0Q"
    "SLVgRp`c0*PwgOA-*-Z*iNumBb&44@XR5XM#tc`Bb<X&Yt~BD_Y)_XDd8QbVCh?YJer0ie&n*=P7<T<s@Qw(Z%U1IO#&G5;%"
    "5U&8*wRPN<3lGH#P;Ta?!9yyB31rb7I-#4amM`2=KgDdu#&oKWXc=I@uS$;)yFj<c1y3dHC1LVMOkl((!9gJF%Jy;Pq(bgMq"
    "Ya4LpAob4QQ?`J8DN0A`8%WVd(>;kHYQv~`4KI2hO=V^P6?JB|E<CzAIxXWRz>o1a&7RxbJz=;LW_kNTzUwa#oy0iiR{U)Cs"
    "A!u@e5etT=`-T?=r<;=&K4!8Ls%g<W$7L$puU!bi=6~~cXxwRFwJwd&pQmh*)tTtUF(KGs&9{@tOKEWX)_gMd?8}$5e>DBmF"
    "IwGs5UKR;l}V;<aGNW&mbZ<<XnO??h-MvxGnI&(~6+>)`QK0B!$hA)l7f~dW1B9lI|3TbfV8X4&V${h8Fgs*#8kfhpBdGui~"
    "AC6F1ZHK;K*|oG-LN9_yrwr3i7~VUgy`^EHJ!&omNx&#`2`5mKTpaAT@Gg>r5(^nmqow$_b>tlH;FfqQ*JAx@C^nBjE;>z~v"
    "GzJ45*bp`RBJA$X~`)Gu<YngF0hD$TT5N`v@IDutaUmi+l-QPKacm8<<pGf57#QWlR$@}W)G6!-_7kOO|un7V%H3!DMAeLzf"
    "HV<VUSmcm4a6wBivZP;{hVVEFy68FqaCBZ5eBurYf?~I07<{bx!MRwB4&TgzZf6fv@n`ub?}NAHbm1lx{C6#Mxrv4ppU-`$k"
    "oQjs=unkWmr5tlL+w*N*WjEG0`Qn%Y&xc*zBk|9YPAjQzbq_NGPz8?Fx&mB_FDP%Stz0LzhEH^S}7};>lXW_*R^*1Ab)*F^Z"
    "Mv)OhhiYZ}oZVKVFmF^8rx3z%QI+41o>Xg;$S;LKj!Z^rv#_rr)d`1`_mE(8#oVkwGU_W;4wVv)fXt|3qsIp`U#sC*|jKH^>"
    "NHmEQ+ue9fEN@rMO*j<l<$-+WroD(&!*kjN|iF@x@)A66J73y;p|9OlS5swbreJ*Z#c12DDU8y!OAxg}`xo{BR*i!@6x(9-z"
    "S4vb<C2X(Y9hg_E|hjm#q@ly+NHS;AXv9&xwbExH#@C6m!wsH@#AdzSJ+PUv}bBqTEVEHJ<=FIZ!&NZ+#`i*P*Wjp-EXdIzQ"
    "H!R=pIr2q8UPHOo)FbC$@bz<}OomRfLfl$CAwS`am<LaRc9rC5|IH_}jWp+hkGmEXLHnmD$pfQd*j$QmeL%LZpOTfhxCpiJ)"
    "i$VIw}s5sQIq^4@Vp2tQ!THP"
)


def _basis_bytes():
    """The basis blob, decoded and checked.

    A mangled blob fails in the decoder before the length or digest check, so that error
    gets re-raised as our ImportError -- however it's corrupt, the caller sees one type.
    """
    try:
        basis = base64.b85decode(_BASIS_B85)
    except Exception as decode_error:
        raise ImportError(
            "kfxtables: the affine basis cannot be decoded (%s: %s); refusing to build "
            "lookup tables from it"
            % (type(decode_error).__name__, decode_error))
    if len(basis) != _BASIS_LEN or _sha16(basis) != _BASIS_SHA16:
        raise ImportError(
            "kfxtables: the affine basis is corrupt (%d bytes, sha16 %s, expected %d "
            "bytes, sha16 %s); refusing to build lookup tables from it"
            % (len(basis), _sha16(basis), _BASIS_LEN, _BASIS_SHA16))
    return basis


def _sha16(data):
    return hashlib.sha256(data).hexdigest()[:16]


def _span(basis_words, initial):
    span = [initial] * 256
    for bit, word in enumerate(basis_words):
        step = 1 << bit
        for index in range(step):
            span[index | step] = span[index] ^ word
    return span


# every subtable is an affine image of the AES S-box, which is why the basis is enough.
# L_A, L_Y and L_B are linear over GF(2), stored as the images of the eight basis vectors:
#   T_A: L_A(AES_SBOX[x ^ k])       1 B key + 8 x 4 B basis = 33 B a subtable
#   T_Y: AES_SBOX[L_Y(x) ^ u0] ^ c  2 B + 8 x 1 B = 10 B a subtable
#   T_B: L_B(x)                     8 x 4 B basis = 32 B a subtable
def _engine_tables(basis, offset):
    t_a = []
    for _sub in range(16):
        key = basis[offset]
        span = _span(struct.unpack_from("<8I", basis, offset + 1), 0)
        offset += 33
        t_a.extend(span[_AES_SBOX[x ^ key]] for x in range(256))

    t_y = []
    for _sub in range(16):
        xor_after = basis[offset]
        u0 = basis[offset + 1]
        span = _span(basis[offset + 2:offset + 10], u0)
        offset += 10
        t_y.extend(_AES_SBOX[span[x]] ^ xor_after for x in range(256))

    t_b = []
    for _sub in range(16):
        span = _span(struct.unpack_from("<8I", basis, offset), 0)
        offset += 32
        t_b.extend(span)
    return t_a, t_y, t_b


def _build():
    basis = _basis_bytes()
    plane = hashlib.sha256()
    built = {}
    for index, tag in enumerate(_ENGINE_ORDER):
        t_a, t_y, t_b = _engine_tables(basis, index * 1200)
        plane.update(struct.pack("<4096I", *t_a))
        plane.update(bytes(t_y))
        plane.update(struct.pack("<4096I", *t_b))
        built[tag] = (t_a, t_y, t_b)
    digest = plane.hexdigest()[:16]
    if digest != _PLANE_SHA16:
        raise ImportError(
            "kfxtables: the rebuilt lookup tables do not match (sha16 %s, expected %s); "
            "refusing to expose them" % (digest, _PLANE_SHA16))
    return built


_TABLES = _build()

# The nibble-XOR matrix, 96 copies of its 256 entry block.
d0x6a0dab50 = [((x >> 4) ^ (x & 0x0f)) for x in range(256)] * _MATRIX_ROWS

# The public names the caller module imports. These are just the historical names of the
# raw table objects -- kept because a caller binds them by name.
for _idx, _tag in enumerate(_ENGINE_ORDER):
    for _sub, _name in enumerate(__all__[_idx * 3 : _idx * 3 + 3]):
        globals()[_name] = _TABLES[_tag][_sub]

del _TABLES, _idx, _tag, _sub, _name
