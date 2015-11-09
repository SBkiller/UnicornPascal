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

program SampleArm;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$ifdef MSWINDOWS}
	{$apptype CONSOLE}
	{$R *.res}
{$endif}

uses
	SysUtils, Unicorn, UnicornConst, ArmConst;

const
	// code to be emulated WITH terminating 0
	ARM_CODE: array[0..4] of Byte = ($ab, $01, $0f, $8b, $00); // mov r0, #0x37; sub r1, r2, r3
  THUMB_CODE: array[0..2] of Byte = ($83, $b0, $00); // sub    sp, #0xc
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

procedure TestArm;
var
	uc: uc_engine;
  err: uc_err;
  trace1, trace2: uc_hook;
  r0, r1, r2, r3: integer;
begin
	r0 := $1234;
  r2 := $6789;
  r3 := $3333;

  WriteLn('Emulate ARM code');

  // Initialize emulator in ARM mode
  err := uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_open() with error returned: %u (%s)', [err, uc_strerror(err)]));
    Halt(1);
  end;

  // map 2MB memory for this emulation
  uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

  // write machine code to be emulated to memory
  uc_mem_write_(uc, ADDRESS, @ARM_CODE, SizeOf(ARM_CODE) - 1);

  // initialize machine registers
  uc_reg_write(uc, UC_ARM_REG_R0, @r0);
  uc_reg_write(uc, UC_ARM_REG_R2, @r2);
  uc_reg_write(uc, UC_ARM_REG_R3, @r3);

  // tracing all basic blocks with customized callback
  uc_hook_add(uc, trace1, UC_HOOK_BLOCK, @HookBlock, nil, 1, 0);

  // tracing one instruction at ADDRESS with customized callback
  uc_hook_add(uc, trace2, UC_HOOK_CODE, @HookCode, nil, ADDRESS, ADDRESS);

  // emulate machine code in infinite time (last param = 0), or when
  // finishing all the code.
	err := uc_emu_start(uc, ADDRESS, ADDRESS + SizeOf(ARM_CODE) - 1, 0, 0);
  if (err <> UC_ERR_OK) then begin
  	WriteLn(Format('Failed on uc_emu_start() with error returned: %u', [err]));
  end;

	// now print out some registers
  WriteLn('>>> Emulation done. Below is the CPU context');
  uc_reg_read(uc, UC_ARM_REG_R0, @r0);
  uc_reg_read(uc, UC_ARM_REG_R1, @r1);
  WriteLn(Format('>>> R0 = 0x%x', [r0]));
  WriteLn(Format('>>> R1 = 0x%x', [r1]));

  uc_close(uc);
end;

procedure TestThumb;
var
	uc: uc_engine;
  err: uc_err;
  trace1, trace2: uc_hook;
  sp: integer;
begin
  sp := $1234;

  WriteLn('Emulate ARM code');

  // Initialize emulator in ARM mode
  err := uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &uc);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_open() with error returned: %u (%s)', [err, uc_strerror(err)]));
    Halt(1);
  end;

  // map 2MB memory for this emulation
  uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

  // write machine code to be emulated to memory
  uc_mem_write_(uc, ADDRESS, @ARM_CODE, SizeOf(ARM_CODE) - 1);

  // initialize machine registers
  uc_reg_write(uc, UC_ARM_REG_SP, @sp);

  // tracing all basic blocks with customized callback
  uc_hook_add(uc, trace1, UC_HOOK_BLOCK, @HookBlock, nil, 1, 0);

  // tracing one instruction at ADDRESS with customized callback
  uc_hook_add(uc, trace2, UC_HOOK_CODE, @HookCode, nil, ADDRESS, ADDRESS);

  // emulate machine code in infinite time (last param = 0), or when
  // finishing all the code.
	err := uc_emu_start(uc, ADDRESS, ADDRESS + SizeOf(ARM_CODE) - 1, 0, 0);
  if (err <> UC_ERR_OK) then begin
  	WriteLn(Format('Failed on uc_emu_start() with error returned: %u', [err]));
  end;

	// now print out some registers
  WriteLn('>>> Emulation done. Below is the CPU context');
  uc_reg_read(uc, UC_ARM_REG_SP, @sp);
  WriteLn(Format('>>> SP = 0x%x', [sp]));

  uc_close(uc);
end;

begin
	TestArm;
  WriteLn('==========================');
  TestThumb;
end.
