{
  Pascal/Delphi bindings for the UnicornEngine Emulator Engine

  Copyright(c) 2015 Stefan Ascher

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  version 2 as published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
}

program SampleSparc;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$ifdef MSWINDOWS}
	{$apptype CONSOLE}
	{$R *.res}
{$endif}

uses
	SysUtils, Unicorn, UnicornConst, SparcConst;

const
	// code to be emulated
	SPARC_CODE: array[0..4] of Byte = ($86, $00, $40, $02, $00); // add %g1, %g2, %g3;

	// memory address where emulation starts
	ADDRESS = $10000;

procedure HookBlock(uc: uc_engine; address: UInt64; size: Cardinal; user_data: Pointer); cdecl;
begin
  WriteLn(Format('>>> Tracing basic block at 0x%x, block size = 0x%x', [address, size]));
end;

procedure HookCode(uc: uc_engine; address: UInt64; size: Cardinal; user_data: Pointer); cdecl;
begin
  WriteLn(Format('>>> Tracing instruction at 0x%x, instruction size = 0x%x', [address, size]));
end;

procedure TestSparc;
var
	uc: uc_engine;
  err: uc_err;
  trace1, trace2: uc_hook;
  g1, g2, g3: integer;
begin
	g1 := $1230;
  g2 := $6789;
  g3 := $5555;

  WriteLn('Emulate SPARC code');

  // Initialize emulator in ARM mode
  err := uc_open(UC_ARCH_SPARC, UC_MODE_32, &uc);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_open() with error returned: %u (%s)', [err, uc_strerror(err)]));
    Halt(1);
  end;

  // map 2MB memory for this emulation
  uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

  // write machine code to be emulated to memory
  uc_mem_write_(uc, ADDRESS, @SPARC_CODE, SizeOf(SPARC_CODE) - 1);

  // initialize machine registers
  uc_reg_write(uc, UC_SPARC_REG_G1, @g1);
  uc_reg_write(uc, UC_SPARC_REG_G2, @g2);
  uc_reg_write(uc, UC_SPARC_REG_G3, @g3);

  // tracing all basic blocks with customized callback
  uc_hook_add_2(uc, trace1, UC_HOOK_BLOCK, @HookBlock, nil, 1, 0);

  // tracing all instructions with customized callback
  uc_hook_add_2(uc, trace2, UC_HOOK_CODE, @HookCode, nil, 1, 0);

  // emulate machine code in infinite time (last param = 0), or when
  // finishing all the code.
	err := uc_emu_start(uc, ADDRESS, ADDRESS + SizeOf(SPARC_CODE) - 1, 0, 0);
  if (err <> UC_ERR_OK) then begin
  	WriteLn(Format('Failed on uc_emu_start() with error returned: %u', [err]));
  end;

	// now print out some registers
  WriteLn('>>> Emulation done. Below is the CPU context');
  uc_reg_read(uc, UC_SPARC_REG_G3, @g3);
  WriteLn(Format('>>> G3 = 0x%x', [g3]));

  uc_close(uc);
end;

begin
	TestSparc;
end.
