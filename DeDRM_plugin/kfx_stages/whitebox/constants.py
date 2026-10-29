"""Library constants for the M1 pipeline.

Extracted from the Kindle Android JNI library (libKindleAndroidNativeBundlerJNI.so
v8.154).  Lookup tables and compiled constants, not credentials, vouchers or
tokens.  Provenance and use:

  P37, B22, fn_table: stage 1 message (kfx_whitebox.message)
  T850/T868: .rodata 0xA59F3C / 0xA5B2DC, stage 2 LCG tables
  T880/T898: .rodata 0xA5C3B8 / 0xA5EE94, stage 4 K-mask tables
"""

from __future__ import annotations

import base64
import hashlib
import struct
import zlib

BUNDLE_SHA16 = "7dbe8e659d152382"
TABLES_SHA16 = "1b50c6ed2f351c0c"

P37_DEFAULT = b"subd6ct97iw2y872w6ew/][83ey02ww][;';l"
B22_DEFAULT = bytes.fromhex("60313d5b273b2e2f6a3738336968656e646f75395d60")
P37: bytes = P37_DEFAULT
B22: bytes = B22_DEFAULT

SCHEDULE = (
    "CDECDABBCDACDABBCDACDABBCDACDABBCDACDABBCDACDAABCDACDAABCDECDAAB"
    "CDACDABBCDECDABBCDACDAABCDEEDAABCDEEDAABCDEEDAABCDAEDAABCDEADAAB"
    "CDECDABBCDACDABBCDECDAABCDACDAABCDECDABBCDEEBCABCDAEBCABCDAEBCAB"
    "CDEABCABCDDABCABCDDABCABCDEEBCABCDEEBCABCDAEBCABCDEEBCABCDEABCAB"
)

_TABLES_B85 = (
    'c-jrufkO+70wD0#tXY{gv(}nPW@aXnOlC5ZOlD>>lguPDlT0!*nIw~BX8JP8OlFcK$t0P~%*^adGRY(}nZB;;bzQI5>$'
    '>iK|HTg#1h_t2<NWGO^v_EBO4=XTid)kMZn|pk@=o@q$~Ps)A@cF@!)eC-a2mNS{ea*O?hKwfc2%9LV$sc2?`by%TA`M'
    '_wG*ici4bE(P;N|EX-rw$4)PTRJ#7IvsBR87r$#~f2+Kgv7@K4KFmfVntNi>(QOnArRI*f~q#dq0lIE+tEIHn`7_=;Br'
    'g=s4lBSxvUxPQJ>*EU8v7>L}QM$jB<i^*8EO)E<bQy^HEf<(Lk15H#oj`~SjrkomhcVfsj6EK3cL*Sh+xEgvb%iy%^Dp'
    '|pi&mn3D0e7V*Dpl8F(q}a$k}ImG*(If3kX7Np-k<N_P9m0SzhGD=y})*eo{F_5Er(lwZ*Xlumt^wb(}0R2MN0>CX@e;'
    '*X40W5tz;1*{Rbq4BRz>3tUiBOUK`yA52@CJpMzm!86bOCVin3C%lXNgzrpnR+MSI`Li2bMOcx**xgj<>DKR>aI`Q-ul'
    'i2$O8eULiyU6zGk2g}APo&8J0`LIFixSDXs>1L1(5@}=#3iO*mmfKCPC%#L4BEpb;|6E{hUT48Cy9t17S~9Y4*Cd?*!7'
    '|b=o2%yi}KctO2H2OVEy##D8MVb}#oG$yhobDWs*&CB)GRqLXZ!$-5dCW<DAq2tX~qoMp8Oaxz)b>ZY_$DLYe@?0cLbO'
    'D=xO7`u3DIl7h(jt3@o?e=Auc2}J2i_SfO;E(R1W)s&ClB5;N27RPMkhOH;c}rJG5B)6RcFldtm5zO-w{_h9#hlJ8m_H'
    'fCt*db^(X6q0+SSEO>Ouwz(df8Vcm}r`u(t(QvDeUvpI;v}wz2)!#IoW7Or>|Kixu7NR)BVt1qG~@*>Eo`99867IWX5%'
    '8}rH+ExT;V%H8R2LH6n~$zs(WK6pIcA3Qco=iy-N6+;)e=R9lSwsdt_F(_;N3j22A+OUn1PZ(Z7uujj*$ZmzNAU`Q23X'
    'l7qjN(c<X?YbyZwLQ&LF%|8en<a~Zb0L5kFgk%!iC0khL)C$U9s==W;Gh&#e`4s-LOMo80f&jI@@H;1>(w{*=38Ww?#K'
    'MRr!~RAKMmYVRWmd8Gv76t>|&?e5g6&n+lS-+`B3cgR}~7&~{@f-N5dX?hRFoC6mR`*}up^O>Y`l$!PAO;wdAFF=dL?{'
    '{T&J|0JdGyFe=&GD!+kk8p~9QW!)0mm;3FJ?>BZYuE40L##OR<$@DcO|d@|`HA5IZ2F?&G*?(zBj{v%o-Ixp!>-3Rk#S'
    '%}L0Qfsn;mw%YkpN!_EI6zj_r7o1S8a`znWvzpN7(lUlE>;Ur)SJaoe!lj&m<;oGqOTzQio*qM!wOt<a-5B>zrZntO3n'
    '>tb>Xvw@|-2@8See46nPV6Tr&$j-BJ1QqH!Dr>*L60x)8VV`W`l!hzqYS6%ugGq`-ijUxsz^Qy&Rutf5-A=87Ulo8G@E'
    'yd2cRo4lQq3VpX+x3z=GcwuxK2p@bXj6_Aj?kNVcIO(h5Uf(HRPfm7d)C!mBDyRDmT&<%u`r-a|r%Y<r{ulWp8hqNMj-'
    '8JU|HA>%&;qXS{Caj(UJ(R`NkmCH1U;S#v?nrda%Eih>y@`?W<nyINjBiE4h?`B?#Oxfc&W-5}pmRoik3;X;BX*bs*<^'
    '@2^|6{wh_q$2SKy^Z>m{#ATJs>=A-i4Rarq+$twgK)A3Rro}FAS`%j16^Eog;d9#g}tpqS_QQyWzjgIzl|A`HZ@jWu!M'
    'U<=7`CO%g0A>Y|)8~Wo%dtsH_*y!T0paqm2#N0yceKC&oWzEF^95;75wDSyES$x-1T#xRH8<y>xgEBSe2myj}88|Cw|>'
    'h6YS&l9}%$L{`egUf9>zZK@USj6jo1T89|OY5qwL#0z65h0PrOG*Lp|6gSW6)1l>goR|TO37!|KIS~EPu&MN%tvC>_OS'
    'd`-LX)Taaz?RvloleG4_uguYhN8E;;jbc1%$-6nH8qL6EK{Oqyv5-uhF`v9^LrOvmSG;xGDQ(N5I*Pd6K)Ujhy#+w6^H'
    'Awxly8d-DXMFCxB$fw56q$vAI6yS&>yEk~Yo+STY<gg&3KT2|RqUw=C6*O-5BTQyo=V0i>g%U02X`%lo;Ku+Vso936yu'
    '<z?LG?3e9g`bQPaDr&Q+e@Bb`i>!|eUd<<7orx};Y}+$Y6hib5ECQbZ?9A>)PFR~z&&m{R+(X<7WWtuzA%ZXgM;^_J4C'
    'i*O=_~@4{K{ibFQ^uWh!p0hRshrN~BWGcOGj#IXYDv%}R@DZ@sF2R~a0$!PS+#ZyZ|mQ;TSM);wiMUL9IZD!_Mr8kpIH'
    'g3Jc!$BuQy_$_sORA%6ghyrIocGs$N??`n$<ymh7(YkHfTk5NnXY+OaRb5xbq2Nit<)odGoyf3(^<#@_w?f{<lVIyJ0;'
    '4-R)dh(0!=_K}^F_>24e`k+BPDcvTE(q~R?BD384zaRjO2FPd4gCHrAlnS*ar!NcWM*YC8sc-wE4>_h5*L*8P~=@sTxW'
    'Uex^CJf-NP<%J45d6vyYJIo+}7`jli$Q_?C0H|93tadc4&y~xGiS0BgI7jdu~2O53*+TAUntm#!Y^OR_QYNbeGqqUaNf'
    '(&y@HuA19o@LByZ&W_>MfBevunkAncElg@Lq;C+o;J+_uSR5awfH|7?6pc!Vf7i^Jc%Y@SD^$@gML}La`?FLK;C{jk;x'
    'r9I2fpyOOL`7k{)E}aVX0l&_>7$)URTh`%cj+{xt$`Vk>z{?HBl#xSdr*%Chc7Ilk;ADjO#W^mX(_@4a!Ji_uZ;FtG53'
    '7lpp@Eiuzw@g*nJ(3rx$bZI9a#9t^n6XxM9GOo&a(Bq?GX}zhh;&aMwsJAlg%1G^MbA-ID1FJ{GLK&Ch95qq0Z;8iR<='
    'NZnrqu*fJmVkRU$Ye2CFAE%QKL@@6$3%l0&NCq)p$5HI6J5{s`QVMq;N8uSj)6XW=KOZZSHWYBm$S!y1@0U7bf1=%GOf'
    'Lu?B?an@<(zt_C*ONKTOAy@2%igdX*w%qGX-WSaaK`D*OZ_IT%-p>tYsVy@^odfgBRQqr4>np*!UeM-a2lKc7hb2NaPs'
    '&fv=gjIGB7*zIYWK{;h2`KmkY#R>iCqti6D$_hQcy>*W%ZF0E5w^6OGV}XRDw$)uz1aTSg3sk~%F4zC)I;cVnSYJmuzb'
    'tzY_SdAY4}>cA#h)zhQ9*FnQdykH-gaM)TlLp?qVnPU73B*o!%XHnynPfWA&D0AvYJ~I-_8y!cCsj$=cecoTBu6mRa(r'
    'kLoy-M~e?uEF^rJNMl^~Y5~!MuZ#K7;zT?IJM@B&h>>fSI(e0FC6d+M&TRrBJj#b77}C!UOyiGomx+uyfisYnJEkb8g}'
    '9j9{7Dnn5RqIkBXf}69-SYkyRUN(3OZlZD{S4Z&C-ZblH(%#mP>7%p=jlope^w;u<tn%D*^HqJY^)L0f>8pVEL9;AJAP'
    'lPs6>hU0hM@Ar>F$iIFpGbB9mWok6z_0~;%9y|66V@33{eWWzV6z4teGY4I)O3j&yisc0=quYAjVSiiaVSK1Tb{se@#w'
    'ozm7w_H|0GkZzx(q)<c+$p$_oO_t#j*OTN$X~=N>hEsE$eFIk&A0GhvR3dF=D#FFqkyW+zH2y$nP<lgcq+<OS`jN{CPx'
    'eFV$PE7QN<X|J+i8f&JtX)pbm52{h^v4NJ1VNS(*qy*b>y*0AY99M{-l`WyZA8vK&hHD)t=MWYII$4$O1}v^CU$rZz#!'
    'fW*SzDd_y{+8kUL<2&xS{gXQz+0=H0^C4wkrck{t{~a%~qJXtQ)?RkZps!uiZbKv^BHAKzRt)^Ei#A?IZ%M!3HZ5nm`d'
    'v9dxs3CsT_Q+p<Ya`R^V{|bgX^x_O_nt8#eq!PUG$t(S8ZfcX4V$>q!LqX@7Vmn#co4#0<5y+TKWo<r6+}R6R@tTFzX}'
    '{Ckl!`oxT_Ns_}QiiRATyd-Sbo@8J#2yCBWYRN~~J8N|vsbkkl>A-`Dny)#)|*+?t9CBxR<mL*8qjndX-+28$DhOcd)n'
    '9H2mh-*1&?ZzPy=xV~<hBrkwQZJ|%k3XxqGqHrffU%$>vVMJEQs6J{#TvAvyDpzTH|;j}4vtHn8Qak7D#_^PLS}T|)V{'
    '=0LxL*o;yGa#gsrUIO&S{!5!&S{zEIpHE$qD%=&iDk%(Jg<m)7MqY)OW<+1lW2svy-r6I@fUAZ{=4vqhPAIyW8!vCbT1'
    'wc?wOpnoxrh!OR8S!jYs1WJh+Nhn^e4^fC2XDAhfsmOz<v)V@18t~z!OAQuom||m~P;Blafw=)daiE89sH=?UEN#oF*v'
    '<JPRMW1MhebQlKMUp>LUR)ZlQXpaf0s=G;9HZxPsN;s*U_uPKuuvKQ0hL`C)?M!&(SPo7qp!Bs|x2R;0E^{m@q@u+Lu)'
    'uW1gzvMu0J%FsXEb<1X@Q`95ppuuM}(0utE<ka#u-I1Zuiu+PknkizqmbNA|_<p)dl7F`bGi+g&Pa%Q&HHHotJ!6sp%2'
    '_UaZ${Ss!nk|GgrwLw+=y)@dBaF|8vmgsnS2#XmHo!s1D#gvJzwPTwtE=C{tQsY&->P>LzaT#7S2s?rEpvg`X%Gh9Hc+'
    'g$I2Ri~#z3QksO#CY)H8BU)-B~9hh_JM@iwFjxW!$#p(x8X;n(3^ZMT{eo%?x4?f$HI&EFomJ*Zz_xkg)_YmCco<nfLM'
    '%%z)H!Fi8zB1`eD*G9j2aQQy;KlB9RS0qEl(JX5@rUoEpRN8GWluH#FcHZPbR5zE1LS*Eks9b^<s)Bm$+D`J0utF1nI4'
    '$rszW^%9vG7uGH;_5i3I6$onDOfI2gv*+Z=zn0FGLm*1z*ASy$6-E2x}XU2vGgU0Y=oEY!X8-c0>-TovWOx*f21)^=x2'
    '&&L;C-lirA~FSF@7S<)vc3Sun>+AU6x$p9N+<##l{@JYiDM(&SD%Y@yzr5OY8s;lrXsRiH{l@yxS;UPWMKQ7wG`;2O%`'
    '7ytHUL;9~WXp|)DFd3^Y-py!is>|OYra0x+SbIs?>;>CQUA^VvG@}b01A}0jO-Z<NxR3HQE(xvszQo9#Z|#~p{>fhi4m'
    'lkvYm$M4QEFu4^W2<5PNCT@YS5j6Z;zK>F(YKam)Q_MY9vB?ckAXgEhlB%B~Sf^LEl*_H`&LKav?{Jue1Cuh482ugYIo'
    'y*$H53PDaDYUw^Lwf8@1TVZ;wUt7(qIfY(0;*Oi<NdO~Ee=?U~<h4HM4jiV0o+D|!nD)Q|6<RElyJ{p!ELBl8^c#7laU'
    '1(fSd0H4;B|~K?q$hNm^pTXeM`;eDy-|ajVYf3o@v1wCRY&{Zz|@*Q-+o^;$`!=?g~iBv0^M-<ohfA5#xOMYxutQ&XP0'
    'g>EcYtq?Ut*2&zN&Q<hbEBjq%XU-r160~c0w7JUG>s3u`3aR3&Rm{ycJIpcE<&>9r05g#s)tGrFL0=Hpta_2yk-qgb~h'
    'V)L(zt+z)tBoZ@wLV+}ER@pDL~l=F!LtTW%MbKymXMs`*p<#4#Wd&&!;_9v&XtKI&|KR!=ijQ;6%WcUyXFpQd&C)1+IN'
    '-OXevQ?tvX*!9O3~n2(f)|3cENVNlLDuxh~UU)9V=zX^|6;e2&r$=3m&mr1wp!eZO3%;`BMw^3GKt{SEM?sk_T&np?Ha'
    'q7|%H)!XaBt161;lbJ?E*8JRV$LUz}#7}sA>)V8Bu%pQ1G!{-{I%G$VZWDir-`d&*JW3%{QUTj5D55naq@az<PTHK1*M'
    '6=t#Co^45SG+AFU3|>ql!k9pkQHN?Uyx_upJY31gktxySKrr#>y2&%f<WzNgFYY2W_F$&K%#M3eVlFE3HW#qhi;mnp!a'
    'QQ)ci`sBb~o6bdkKIkz4&dt^(=`|_L6MDXcqQ|n@OVFA20N=P4AK=60&Ox_fKusqxL7yeiYFzl}A0AwX~Eu5Qnpa8A<F'
    'e)c)tG}9tDGX`5-PP0)l^Z9vU{<A;w=If3M_6uJ4&W!cMMU#U-Cb;|=9J~2WJv`z=W;f|^LD6~T1{V=nVKIuQH<Ro+dq'
    '1U&M3TRTv+%$XA7!Ky{BQZna_q)H=53I=8w~L>!@AAUA45%$kHmvj^rL)P+73UCf}a^n8?g0l+<}zQfUe_K0U7^&eN!D'
    'k1)JK>e{!Lf}+8_3#|L=tMP8d3shcpY*nPOI`>2sES6LK!l}Tid9O<kQj_crpc=s>G9)3Toi9f*FOR!TO9l>8qjR^hzt'
    '{a_wU0%0&%-S7w3Q^4PcMz~Oz)~UhS#@c$CWQb9VT^K*7Rjou0z>kN|LJUJNmqR3;9dDe;nQ35(J(z3GU})GoAxV``<F'
    'iUZbh9WIjX*RL0T@K8WZLPJjgbLD@8sK?(=ID}73NGq}2UW8j0ilX;;xko*I-vT{2S<T^0eD!C}To%=32wBvh;M^T^9Z'
    '4F08r2e4YlM&^a(r<!o<ddnQ_Jz>*-kYtjO7Bw_w4WRU_HGIAn&-p**e{faW<3^^w8u6CLDeLatghloC!+ZsbWxAdHN9'
    'yaqY$}=nkA|)%{J^TSTEaZOo!&yeDd2^Q^P8?9;ujJH5{zHW%^8G)Hkb&V6*8*yqhy(#qrYDeXpZSJI>-xbzDb*KxZ^R'
    '%F|FGj<vj#mRID={w|8iY9haKq53wvEjSOQEVq+|joz&K2Il2|^nFgQARdUDk`vo_6uE(jOn+gHwf_eA@-u6b(FL4@US'
    'ciGkMquBy>p!(_l+-aBDl)=Zpz%jjEtMq*-(0nh#XQyvp?v&hQH=6A9^l3B<B+@Xt$uh%ayRF={(z1$-c~svKM+Mm*-p'
    '7jKBsZ{*frsn+xs{{oN}d)~sDgahhpixRSL4y>;d47eF~Fxz1RI8;4o5p#`z~P`j)349jpmq@(@?t-NJTR!d^HaeEtZV'
    'AB8txQ&wuo(GHOHu1a#WWEUQr24Z>eQy*3$zPz%_#1iAE~kFWFf9vcnN&ZCi!S+?PHjJC1Lr-oaw-3`wdNmAU9F3uUPv'
    'x3D~G@I(X#7?a1&9^Jv1Ot3zcH0#<8pmL35n#JvVu8fTwb%<~p)&k!JL*s?pTNq(IE2%uPzHI^RZ4YA=Fj8?5u%x1~Im'
    '&9+38DuAxiP{v+zrMkt*1}JKS5`gI${JPj9HhAm|-I9_#`QnURC&*q?zBtWQIM+4DJ%5}-z1eNf{N#9w`_-4Hk(yU)Id'
    'VeJUBMpb9pY68+4m{ABfuC@19MraiRGD-0BdV6sFf@^83PG+>kMgrZn~-S9i3#oQkTpx)c>?@bj}!os6J=#+52SnVKwo'
    'j^lDL7L2V(mIu8>j{0EItl_yx^(awaLi~iqZcIG{^#8!)bDqkRPFdeU{0+^GlC|h{XNY9i7w#y_4L|Dca)1?<Mj_BA{1'
    '(+kc((w|zE;b56sk;adF+Z+)C0*lE)`ttWRu?&Q2WH7Qe1~va$08Uz`h#gF4m*0<|AcwN)`onPm`}T8TBx&Pzvi`+*Lh'
    'EHc>W)(jFiaHHR-vrh{BIuJL=n$XOxo~DWvSg(4pVrZUM34NV(S41ie%ABuw2^;lIiR$`4!S@!EY42RpN-;%))gQXtwp'
    'or)?dY@4S}grTn*t13kUHki+6y7L{)I}?_+T*ZCO+3F?h=f_7h2y=dQ2iQ`5V$3=2)s`LUMd&!#Ry?Hb{oo#Mg>Z}fYv'
    'Kq0TV90n0J0r^9fOu2STit3x+UE3bU+on?viI}Ji{1NG*x*^vCBON&+Rx2UkO~VCwSB1^9Aw&iY=e6EDXXnO8hZ5QEL('
    '|b<M$UQm++0vD}QUstJW{NZ9C6`3d!_GI^~pGET!whrcw=C^F(_YaYZGI-m_tN-GeXiyFdiB;C?URJo=5eI@Z$@`Azx!'
    '_sU7MebisIazXv^S#8{xUBcW=y8Ffp#b&?zFkR|630X%V8?l#%<nWF20cvwDUW1}a)N4ZW(6?SpnCeg=0oE*wTa+oYLa'
    'Vl@%o|E+|`Je2JHAEXiYi{gdAez&ymlvue1W}Le$5JNhq&q)|jlAmfT?6lZ&tZlb7hZ(=wTPt0&TXRPwGSF)i3qL1i+o'
    '>h=n1^Ljx!zO3R{<k$Xledp9i{F{bR^}K@LeSezgP*yPJsQ1eN+V`5NZv5cMB!l~D=go9<$8OhQ4WwiVHM~0{GgSTC@U'
    'A&r_D;4#X-H@_-yIAZzLB}F^JUiMs*`S#^CxtguZ6W)Sevd-ey%L<_#&lXW8)Xb28*QKk>h}rE%vhkV_sU$*Rdc+Oxs2'
    '%pz47sxa+N?&^MXy_dN$qR`G1NhyOMw`K*p@owDIf@tzckRpLea%ZNVrQtKUP5HO+i|JO_TH=EoDz}oxw*)ug3HKltC='
    '8xQmoI7;TElplSSqkN~NXMl~lcYDe(M4AY+gcW-{?151Z)Ps*TR!@z*}<Kh`voz-g^F}%atto(Hs;9|XBWLnX1_P8s@$'
    'Xj4I%pW7Fc_hyHx{xAg%DSU|-co-HJ{(>~`gM?;gNkm~-?*JhCzt%qp{`hLE?%?o3YOkxH`)W?1&M`H&z;F{RLitt_HF'
    'Pp(bhmPIhbs#X-7PPP)rrD0>H_O<4XfInDGdI)%fiNn}}T3m27=@N@M@v6UpBDAa|eE~M*MdjzV|I9Uy=h+T<gzV|`us'
    '9M@AAfUjgME&04*y<L@%T>QY}HN@Z{Vz*-*mF}H$5Bd$bShZ!_MZ-1+4IavmT82R3Vv*ZL{3eu0WWexej;9ehDn=Eo+0'
    'N1G!@SGmbCSNt9@uJyWRndvc8``+P35pE#P-hZu>A2^Yt8>c|CtVv!0?><KL{!viQk9KS@t&48H6t%=wlE?=I?wc3YGE'
    'X8DiccS0pcBOc53!Iz5x6J4^nfJ-i?V|l-51myLEA6e!GsR(+`}G%1YhpsfTBX0ErHNYG*{;c?X&IYqW_2xNu(PP$L7v'
    'NTuz;Tbgytfk0@HgAQQ>)rDpSv*rXQr-@^3NA3OHpbPrAqK$fL>fviYw|z~t2|k=0!bX;I>sh6TpiNp*sjmKz20Dz9*^'
    'S)Mx6$%m-`WJiBej;(Pq$kl)f)ON6;H)CftUb8-SLu=(c!QgyKJZ91aG^VHIL9s6dnE)2bm@u5*|CpNZzn;VG-K9zGKV'
    '*c|?#|z?7U?25s?N;j%?)|@!~A6icQF^lPp|1+OkAX-D5Z+?gl6A;`fvNK*c-_EPQN=}rgV$>>&J~lmvJi#<6}Og<#ep'
    'Uo@$v^mqa-xUD%r^{8aSN(gxW#%=JJsPIkh)&4F30=J-Etu1=2JGZ<5Gpru?37%0v8(G=PKsM)7WQ6>*<<&zuO_34ca^'
    'Ucu+esIqNs17Y=2H;`U_YL##XVhW3XjAQ2$4G=Hs%>e~&p01(PKSNeQ8?f89JSGzVW4Tl#Wol~om9VXd{V>tSW3?^`rB'
    '+4=q2b!U$xdCl#{>MBGRhRHMr*)&n843#dtj7MNN09n}4~B#h?J+;#W0A@ptw>v-2yt<7nmg{OX#^(17<v5u*G9wG$<g'
    '<X|H?d$ME=X}u3SO1p|oXOq@K&K9jF2-!1Lms(b&O?QI3=KA->W-zjBR{4(7Px-LGN;_eK7OxZ*cr^T6@kx1buA;9Ka<'
    '%SH=20d;`82#T??^Vk@p<&?&YvSE<!7oP^xE;${eN%}`l|*>*}*Yp@7eV2+9~}?c1PlOmkkzSH8>uZhWAIrCJvUDH~FW'
    '-7F5oGC(Hf_dy|4J;#wRN4sng8ChhShbu3d}?mD8360vb##s!?eife#TT{9&gCT2Ocoz6BsFVLtW%&n{_s<a_Y(RCc}T'
    'LA*RaQM@JukSuT3v6><EyE6<pXf}eCT&b{$F@zxnP%|Tsdi<2ch2nxH-kMO(Qe&B^dSOHP+0ob|2G7e#s;_6S0tTFYKE'
    '2w%i2R4chZE4W9jRNu(k(+SB1A)!-%WfYlJbacffl~o4EdQp!`+USvFIBN_Dz9c?1AWi4OPNt}|eYC6f#v2G2*kOWTPn'
    '3U{+*74Te)VUJ0N*P-@hqLS~I5iE{@?L}QVZ4J}vw~pRVTG8;aj~;gmMPMKUpERP{V}4WLB<~v8P1aw`U-;A9Kbf;CTj'
    '0lQeuotkI&>!D_D<diR}M@mk3WiB9G!xD&_&G=q0)M<hrvKg8_Q~rxN>0WqN?h(sj!wWW@PtT#M8ir-rZa~{$inx6Oq2'
    '$vvuHYpv$vN+2*{N)#3iaz;ezv>O`lC!mE==y5g49K*lPwhjtLLuB&u#3I0yTxyHZKG!=PN5w>1^k8-^w3#KFBX&2x%M'
    'awJJHLe=oTc4J67!Nc3mHkNL#lBUx#?3YyZ+wc0(3FXUr4iV?)S#iC)F)i+z)Nye>srh2T2Ws6$kX<q%2_pVULG<Pu*b'
    'OxV>jpPr5wDHZ=FUuS*@yCmM3(cO5M`?UU9MUroOeK3cDDSP)QW5CzJ{8O;fTjHT9M=o0fL0Or#5rjD;y*_9LuXQztc|'
    'd`8Ud#K)Su8Lg>rD}l}PGVWW&%`>gl0s!D**>BJT9x(T4pFRm+!zgdVKJR&7#Z5min@anoOKjUR@TB1tIH`VZJ(Kcy_^'
    '^l(cc9xzW^-0VhiDJ@@FkPTRPl0pNA&WM&PHffP~10&sy`0@F56d+>rQAe(6*#Xo4kcr>7v9tUXCW&+$}d)GX)78OQN8'
    '467yqcL><8FRPf4$nU3OClmJxLOCM6e=7NG$bL6b<X=7{B7Nz`B{Oo2aziNu;-=s$gdd(G+s{CxCH0kr$mjp3(Z`F>`A'
    'Kb6i-v-n3{wfe7x_z^S8^Mv;DS5_`i<ar~Q@E;@pos-KW2!-A@=L29RmN~TfnogL9N2ifSOJ(%=^BHJT-A$E+rz%MrwD'
    'U2U$Uq8!UiC&qS99u;b1~#M;<mUCXDOYBT4DsB#vx5D_oZSS2Ch2Sh*-4;Fy_`(5wXjJae%HOab{i1uJ&2z`*dD=ky+Z'
    'h7$@^aUUi+DGM4Fj7*7rJs8S-2>_-|);F7___bL@M3<y@BsqSAXjum`{au|D`MdQHIM!Oj1>_wZ40l92j6(^&l)-1QWq'
    'MhrO4XAwWhgwcxuy~ZWdw_m<f$Vw$4=r>aWv#M#!6v)&mZn?&|S4zwWzfstF4Uy**uI5{9UvIKppIkE6;Kkyv5FU!~*x'
    'BIlc|W?=jeB8K{66-}<fWlH%6HMWv{Yz(|c<NV{5nB~xkrNwPKs(_Ur;>#uXbj%0RgUO1$o@ojWEVo8>z^2^w!{`Fmd6'
    'W;a-`lbxs1V{>-@<VV@6Go8Splp3uZjSpUJq^4}f|{Pn&Nfh+T$w9Vt`CvMXKD{Y?(6XUn?)<l-;xruXO0Oov7Y7i+1^'
    'vb2V4spHugo@u8x@a8A+zRZ_*caW+5N%tBWv+v|r-c85;`ywYFh0=~w!9fR&lbY{YG?xu=OVT)==@9>;eoUlmN^wMx30'
    'IgZVc-+@qjNXxFc6WD2}@`h5R26TMz4O0kXmOO(0Gu+k01-+UmY(bTtM&0X)sDy<{vW~PBr_W>1b?pO|%$$5=TW!q;<0'
    '6BGyCZHXKQyjde_v{5-4O?{yGL&EFxL2bw#%dl>8}ic5RW>m^Vha!kFrO+3Fox3mXFjul#P-{t;LPm$x9Mvs4sSr)8=*'
    'r7toSc+i#PLl2`?6E8cSsiRZB+6YdML#X&K<Wl!1u;=ReKi9z5J<;k+C)O&b^R^79`e>Pz!;XZr2Sis&|e6ZI<I_8gRV'
    'HGl+Ytxh_qw}?XyQg;iQuQSB(bQ*}Es6UXQ`$O`3ew=+rq+DJQJRv%v|gG}z-QsTN<Yd;eA$bFMnkv6C1ZiC52L}&MV1'
    'eOGEfwaBK8Qv45*=NHC+rUy&;WZ$P%nYF6TzE_mc7~W!BK-wZ;>}#hI?W#f*AuOh+MhRt&?oBeOVGuj5f7(<;g~YHqOR'
    '=ALxX`qP~GI-sma1?apUKdS(mccD;|?rv<#Zj5zUw3?Y+7Xm50F=;qAIQMls%vgs}#==Q^66m?plHNlXj;;mnY4S{PQY'
    'PhYz+?2UGoK7(Wh8@ESC_Oy({-pod8&IOzb8@VyRDp~`JG>v12MI?z9!t@&5tcE-CWQKGDKe_$7i39{fUyAPI)G|3X>;'
    'QG`N7x$o_o5%s{YeV{Xk@P9MO%*ZHnBqNA-iN_TAdY|df0)QU_4_Rng>A|GbF)}E7oNX5FmDCEFBZ+2sMpNcz=j)fm?2'
    'bkY={1`vrXAQ%Ni~BA{KWcjJzmT>s#YnqdxH^8i8;Q;v_K-gj4}xmjRp=9{?a7-bP#g$)b@9gmIU=Yy3$sbTxrFMvQq*'
    'EeV#F9`g8=}Wf5GrC{mJ;cLULjVC5ATDkP4X!i4#oi*l0}dXVyJyDr>AW&rwn-i$_*CfVxoqgPzBEU(4<##abBdUk!%|'
    '$643t;Vca%k#Zm@Qnomc!CFoPmV<<|$Q21o7*2q?bdUQC{pdIej33Brr)w|r!zz!t-T)5*5`^aw%SY}wzEwUG{oMo1V&'
    'i4x>3CM!F}el~fIc3@H$9*~47-Z_n{ux(802hxk&{<a9Yd_Xi@K1R681PLfApXlrCgs!;t>YF`(NdTBkB^<WqzQw6`g-'
    'wod9`amvlWN`~c#>5c+Ax`T%+Sk)tRXR}u<;+j$tU$o)M&si2{(4SI>THxn)t@wU~7hilRJEQ$KEXl_F!ZkqXpeOBJK)'
    'JvkUT9Dv*lCG^W4OY}%eJguDi0NC>F^5r^>t&St{wSULDgB>&P88-0&&>tXCk=lEHBQ{FNik&?9kQJA?ymE;2D2YbM8l'
    '`}m->S=hbvz8#TzF<VLkP#W8{CTIX!D@wsGnp8C4e?izExUy}7fw-|V7_sc1)~Ft(6*%dijjnfK22j@2VZ5;hkeqi}U^'
    '*gNW<5Pz3nC}b<l(48em)mGhRRM(&}yJt|Fu_bYi&WYR_Coq7W%dC^~F-B+>M1Q51<$2`>6tv~P7(%6X_33(T9hZrB<^'
    'G8*VIFSj2(t1(>p94tq3G^{+W5vt+B5QG?@Aphu(0o`J(vY>Rk$W6J(h#$lLxLqxrs;+yt^9h#0QmFvgSyd>poW%v@kF'
    'a6(@s(l*h?uE5b%*V}lV|W6yxS>sZ-#4?==X-l>nxkJmLP{Hd<D%Ly~6iiDSmGY8M4M3+Bj|0A2Od8<e)%4ZX#VeI$%*'
    '{El|Um5CzEipS&H<d@1{osMwA+*xU>CsTap`4cZCx(iNT9HTpJ-eA`Dn-PGNuLk>u&o!L<3YsN)f-x_8_N98Bu722Dva'
    'tV*T_3iCFknUDJkc{e`+-?^{g^;%IFMny6jplkm9O6rRt{b%Qz;?q7>y|%TmQ|xxE#n%w(<;#X5pq4T|vo&}P=e2MVsT'
    'DeVpXBW7pYa}3+FJK9t9nJ+AhsdEz8iq4q75v1;KVL|!z2?o(e#%^j{%ANKru8!Q4IAiV%je+<*PVAZq%^v<ffU{oD7I'
    'YPsER~xQkOiBi0AB-hZ|S76Gbtx*pZRa=b+wfP$v!^>Rb(d28fnJeW}j`2mh6{BFp?SX(~fK3=odoPIO5`QT#AWVliR%'
    'ueYh12{|#G$5YumRPFt+RXYtP^;VH3DL@A@ogw5=g3WSaWUXWa<#iV@?K<git$Ru+ut19!d7RzN=OH5SJg20Q?JJzSrZ'
    '8de!Mrup_)ar<yppLuP3;l&4qIZGg5p;Xu^Xg8hL;cVa+UKnKsd=8(W=-r3^5*1Tk{6Y}P({)?gyNwzDH9T5_Nxx*gc{'
    '%KMYA4wj(v@9mu&<+gN^(*rsT5Zxi1`j>gSzK*ngt$Pr6vU@*&am0XXTzxw&@(V#g9by_4u|U+293LEEwHF75E2bseIG'
    '8*hQn8ef#y2>*E-+4(GY&#pA|18mHm0}UR_67ut|*Z2P=HqV|nXUnt*=C`_T@%?j6QJbDO+jji>A3**1XmL4DaRkQSrE'
    'xA>eDv0TXNmbM^0Y#oqqqx;q2z9JO#NRG>-4`CM1}MIJ2d>i|MTBNk~Q>}clcD!tjb@t#g;VrHNmE%`&+QomDqD%rvGd'
    '9=HA!;EJ`rVn|STM^FOvesIuPlu7j-FCQyzCPbgmgIeJ%h<j;SWtcElopLp1_Bc2?0-}@hokN@}I|2kG3^3E{ydS&zCM'
    'Q3OJe&LYcRb(_0{(Svs?#UA+*V+yTh$kk_PW{)cw4Q;R0RPWO&oK#WWeaDZAO1gE@<*UK=t#Qp#)`%T=gt&=t($_+O#k'
    '`m=iF&u@@fAD{JVWtMd**FMEl#x&!(ym9cq8;wfuWVFgRo>t_Klwcg(%?R?PL=n5*?4;>P(22RCfMbD@)e0Dw8k5x1hI'
    'PJgwwLaAk?hJNS0V%+*~;xwJ(+zrz;<jtE{@5*e&mGv{bjyC5EUhcKWXg9d8g}=`_k+B2Gj;Q+8@61}xyMBlA@ysEox$'
    'aL!W}))D_Fd(w6ZX@!89#Rhsw+}u*Izt!t|q<^%vP{w-_WOc{?9-3=Ogn#<VScVp!?kJX%^g?Y0lSEhQC~2f9D_0tjpj'
    '2mDzJ3xs^X>$Nvd${>WjsL!uTQ?zP!D15Ngeg6Unze7!L9M|j{r<=r~Y>-=?J;lDc+P=K;x{!`n3LSpwV=eHUE8~Tyyl'
    'Fl5Q{U$VI`Ty-L{_*R3cfn`O=4~NU=59}x2LC^BSKD*'
)


def _sha16(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def _unpack_tables() -> tuple[bytes, list[int]]:
    try:
        raw = zlib.decompress(base64.b85decode(_TABLES_B85))
    except (ValueError, zlib.error) as exc:
        raise RuntimeError(f"constant bundle is not decodable: {exc}") from exc
    if len(raw) != 11429 or _sha16(raw) != TABLES_SHA16:
        raise RuntimeError(
            f"constant bundle pin mismatch: sha16 {_sha16(raw)} != {TABLES_SHA16}; "
            "refusing to load partial stage constants"
        )
    mags = struct.unpack_from("<5378H", raw, 0)
    signs = raw[10756:]
    vals = [-m if (signs[i >> 3] >> (i & 7)) & 1 else m for i, m in enumerate(mags)]
    return raw, vals


_RAW_TABLES, _ALL_INTS = _unpack_tables()

T850: list[int] = _ALL_INTS[:1256]
T868: list[int] = _ALL_INTS[1256:2335]
T880: list[int] = _ALL_INTS[2335:5078]
T898: list[int] = _ALL_INTS[5078:]

FN_TABLE: dict[int, list[int]] = {
    w20: [
        (((w20 + i) ** 3) if i < 13 else abs(T850[i - 13]) * (i + 10)) & 0xFF
        for i in range(256)
    ]
    for w20 in (0, 1)
}
