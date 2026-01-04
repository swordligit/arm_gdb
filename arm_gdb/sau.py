# SPDX-FileCopyrightText: 2023 Max Sikström
# SPDX-License-Identifier: MIT

# Copyright © 2023 Max Sikström
# Copyright © 2023 Niklas Hauser
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the “Software”), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import gdb
from .common import *
import traceback

def get_sau_common_regs():
    return [
        RegisterDef("SAU_TYPE", "SAU Type Register", 0xE000EDD4, 4, [
            FieldBitfield("SREGION",  0, 8,
                        "Number of regions supported by the SAU."),
        ]),
        RegisterDef("SAU_CTRL", "SAU Control Register", 0xE000EDD0, 4, [
            FieldBitfield("ALLNS", 1, 1,
                        "All Non-secure."),
            FieldBitfield("ENABLE", 0, 1,
                        "Enable. Enables the SAU."),
        ]),
        RegisterDef("SAU_RNR", "SAU Region Number Register", 0xE000EDD8, 4, [
            FieldBitfield("REGION", 0, 8,
                        "Region number. Indicates the memory region accessed by SAU_RBAR and SAU_RLAR."),
        ]),
    ]

def get_sau_region_regs():
    return [
        RegisterDef(f"SAU_RBAR", f"SAU Region Base Address Register", 0xE000EDDC, 4, [
            FieldBitfieldMap("BASE", 5, 27, lambda x: format_int(x << 5, 32),
                        "Base address. Contains bits [31:5] of the lower inclusive limit of the selected SAU memory region"),
        ]),
        RegisterDef(f"SAU_RLAR", f"SAU Region Limit Address Register", 0xE000EDE0, 4, [
            FieldBitfieldMap("LIMIT", 5, 27, lambda x: format_int(x << 5, 32),
                        "Limit address. Contains bits [31:5] of the upper inclusive limit of the selected SAU memory region"),
            FieldBitfieldEnum("NSC", 1, 1, [
                            (0b0, False, "Region is marked with the Secure attribute and is not Non-secure callable.", None),
                            (0b1, False, "Region is marked with the Secure attribute and is Non-secure callable.", None),
                        ],
                        "Privileged execute-never. Defines whether code can be executed from this privileged region."),
            FieldBitfieldEnum("EN", 0, 1, [
                            (0b0, False, "SAU Region disabled.", None),
                            (0b1, False, "SAU Region enabled.", None),
                        ],
                        "Enable. Region enable."),
        ])
    ]

def get_sau_dregions(inf):
    SAU_TYPE = read_reg(inf, 0xE000EDD4, 4)
    return (SAU_TYPE) & 0xff

def get_sau_region(inf):
    SAU_RNR = read_reg(inf, 0xE000EDD8, 4)
    return (SAU_RNR >> 0) & 0xff

def set_sau_region(inf, region):
    write_reg(inf, 0xE000EDD8, region & 0xff, 4)

def is_sau_region_enabled(inf):
    SAU_RLAR = read_reg(inf, 0xE000EDE0, 4)
    return ((SAU_RLAR >> 0) & 1) == 1


class ArmToolsSAU (ArgCommand):
    """Dump of ARM Cortex-M SAU -  Security Attribution Unit registers

Usage: arm sau [/habf]

Modifier /h provides descriptions of names where available
Modifier /a Print all fields, including default values and disabled regions
Modifier /b prints bitmasks in binary instead of hex
"""

    def __init__(self):
        super().__init__('arm sau', gdb.COMMAND_DATA)
        self.add_mod('h', 'descr')
        self.add_mod('a', 'all')
        self.add_mod('b', 'binary')

    def invoke(self, argument, from_tty):
        args = self.process_args(argument)
        if args is None:
            self.print_help()
            return

        try:
            base = 1 if args['binary'] else 4

            inf = gdb.selected_inferior()

            common_regs = get_sau_common_regs()
            region_regs = get_sau_region_regs()

            print("\nSAU common registers:\n")
            for reg in common_regs:
                reg.dump(inf, args['descr'], base=base, all=args['all'])

            initial_region = get_sau_region(inf)
            for region in range(get_sau_dregions(inf)):
                set_sau_region(inf, region)
                if is_sau_region_enabled(inf) or args["all"]:
                    print(f"\nSAU registers for region {region}:\n")
                    for reg in region_regs:
                        reg.dump(inf, args['descr'], base=base, all=args['all'])

            set_sau_region(inf, initial_region)
        except:
            traceback.print_exc()
