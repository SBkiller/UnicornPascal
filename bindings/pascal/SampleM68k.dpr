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

program SampleM68k;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$ifdef MSWINDOWS}
	{$apptype CONSOLE}
	{$R *.res}
{$endif}

uses
	SysUtils, Unicorn, UnicornConst, M68kConst;

const
	// code to be emulated
	M68K_CODE: array[0..2] of Byte = ($76, $ed, $00); // movq #-19, %d3

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

procedure TextM68k;
var
	uc: uc_engine;
  err: uc_err;
  trace1, trace2: uc_hook;
  d0, d1, d2, d3, d4, d5, d6, d7: integer;
  a0, a1, a2, a3, a4, a5, a6, a7: integer;
  pc, sr: integer;
begin
  // data registers
  d0 := 0; d1 := 0; d2 := 0; d3 := 0; d4 := 0; d5 := 0; d6 := 0; d7 := 0;
  // address registers
  a0 := 0; a1 := 0; a2 := 0; a3 := 0; a4 := 0; a5 := 0; a6 := 0; a7 := 0;
  pc := 0;    // program counter
  sr := 0;    // status register

  WriteLn('Emulate M68K code');

  // Initialize emulator in M68K mode
  err := uc_open(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, &uc);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_open() with error returned: %u (%s)', [err, uc_strerror(err)]));
    Halt(1);
  end;

  // map 2MB memory for this emulation
  uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

  // write machine code to be emulated to memory
  uc_mem_write_(uc, ADDRESS, @M68K_CODE, SizeOf(M68K_CODE) - 1);

  // initialize machine registers
  uc_reg_write(uc, UC_M68K_REG_D0, @d0);
  uc_reg_write(uc, UC_M68K_REG_D1, @d1);
  uc_reg_write(uc, UC_M68K_REG_D2, @d2);
  uc_reg_write(uc, UC_M68K_REG_D3, @d3);
  uc_reg_write(uc, UC_M68K_REG_D4, @d4);
  uc_reg_write(uc, UC_M68K_REG_D5, @d5);
  uc_reg_write(uc, UC_M68K_REG_D6, @d6);
  uc_reg_write(uc, UC_M68K_REG_D7, @d7);

  uc_reg_write(uc, UC_M68K_REG_A0, @a0);
  uc_reg_write(uc, UC_M68K_REG_A1, @a1);
  uc_reg_write(uc, UC_M68K_REG_A2, @a2);
  uc_reg_write(uc, UC_M68K_REG_A3, @a3);
  uc_reg_write(uc, UC_M68K_REG_A4, @a4);
  uc_reg_write(uc, UC_M68K_REG_A5, @a5);
  uc_reg_write(uc, UC_M68K_REG_A6, @a6);
  uc_reg_write(uc, UC_M68K_REG_A7, @a7);

  uc_reg_write(uc, UC_M68K_REG_PC, @pc);
  uc_reg_write(uc, UC_M68K_REG_SR, @sr);

  // tracing all basic blocks with customized callback
  uc_hook_add_2(uc, trace1, UC_HOOK_BLOCK, @HookBlock, nil, 1, 0);

  // tracing all instructions with customized callback
  uc_hook_add_2(uc, trace2, UC_HOOK_CODE, @HookCode, nil, 1, 0);

  // emulate machine code in infinite time (last param = 0), or when
  // finishing all the code.
	err := uc_emu_start(uc, ADDRESS, ADDRESS + SizeOf(M68K_CODE) - 1, 0, 0);
  if (err <> UC_ERR_OK) then begin
  	WriteLn(Format('Failed on uc_emu_start() with error returned: %u', [err]));
  end;

	// now print out some registers
  WriteLn('>>> Emulation done. Below is the CPU context');
  uc_reg_read(uc, UC_M68K_REG_D0, @d0);
  uc_reg_read(uc, UC_M68K_REG_D1, @d1);
  uc_reg_read(uc, UC_M68K_REG_D2, @d2);
  uc_reg_read(uc, UC_M68K_REG_D3, @d3);
  uc_reg_read(uc, UC_M68K_REG_D4, @d4);
  uc_reg_read(uc, UC_M68K_REG_D5, @d5);
  uc_reg_read(uc, UC_M68K_REG_D6, @d6);
  uc_reg_read(uc, UC_M68K_REG_D7, @d7);

  uc_reg_read(uc, UC_M68K_REG_A0, @a0);
  uc_reg_read(uc, UC_M68K_REG_A1, @a1);
  uc_reg_read(uc, UC_M68K_REG_A2, @a2);
  uc_reg_read(uc, UC_M68K_REG_A3, @a3);
  uc_reg_read(uc, UC_M68K_REG_A4, @a4);
  uc_reg_read(uc, UC_M68K_REG_A5, @a5);
  uc_reg_read(uc, UC_M68K_REG_A6, @a6);
  uc_reg_read(uc, UC_M68K_REG_A7, @a7);

  uc_reg_read(uc, UC_M68K_REG_PC, @pc);
  uc_reg_read(uc, UC_M68K_REG_SR, @sr);

  WriteLn(Format('>>> A0 = 0x%x'#9#9'>>> D0 = 0x%x', [a0, d0]));
  WriteLn(Format('>>> A1 = 0x%x'#9#9'>>> D1 = 0x%x', [a1, d1]));
  WriteLn(Format('>>> A2 = 0x%x'#9#9'>>> D2 = 0x%x', [a2, d2]));
  WriteLn(Format('>>> A3 = 0x%x'#9#9'>>> D3 = 0x%x', [a3, d3]));
  WriteLn(Format('>>> A4 = 0x%x'#9#9'>>> D4 = 0x%x', [a4, d4]));
  WriteLn(Format('>>> A5 = 0x%x'#9#9'>>> D5 = 0x%x', [a5, d5]));
  WriteLn(Format('>>> A6 = 0x%x'#9#9'>>> D6 = 0x%x', [a6, d6]));
  WriteLn(Format('>>> A7 = 0x%x'#9#9'>>> D7 = 0x%x', [a7, d7]));
  WriteLn(Format('>>> PC = 0x%x', [pc]));
  WriteLn(Format('>>> SR = 0x%x', [sr]));

  uc_close(uc);
end;

begin
	TextM68k;
end.
