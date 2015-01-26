library MemScan;

{$mode objfpc}{$H+}
{$macro on}
{$inline on}
{$modeswitch advancedrecords}

uses
  SysUtils,
  Classes,
  Math,
  Windows;


var
  OldMemoryManager: TMemoryManager;
  memisset: Boolean = False;

type
  PUInt32 = ^UInt32;
  TIntArray = Array of Int32;
  TByteArray = Array of Byte;

  TPtrInfo = record
    addr: PtrUInt;
    raw: TByteArray;
  end;
  TPtrInfoArray = Array of TPtrInfo;
  TPtrIntArray = Array of PtrUInt;

  PMemScan = ^TMemScan;
  TMemScan = record
    Proc: HANDLE;
    SysMemLo: PtrUInt;
    SysMemHi: PtrUInt;

    function Init(pid:UInt32): Boolean;
    procedure Free();

    function GetMemRange(low,high:PtrUInt; dataSize:Int32; Alignment:Int8): TPtrInfoArray;
    function CopyMem(addr:Pointer; bytesToRead:Int32): TByteArray;
    function Search(targetData:Pointer; targetSize:Int32; Alignment:Int8): TPtrIntArray;
    function SearchBoolMask(maskData:Pointer; maskSize:Int32; Alignment:Int8): TPtrIntArray;
  end;



//------------------------------------------------------------------------------

function TMemScan.Init(pid:UInt32): Boolean;
var
  sysInfo: SYSTEM_INFO;
begin
  Windows.GetSystemInfo(@sysInfo);
  Self.SysMemLo := PtrUInt(sysInfo.lpMinimumApplicationAddress);
  Self.SysMemHi := PtrUInt(sysInfo.lpMaximumApplicationAddress);

  Self.Proc := OpenProcess(PROCESS_ALL_ACCESS,False,pid);
  if Self.Proc = 0 then
    raise Exception.Create(Format('TMemScan.Init -> PID %d does not exist', [pid]));

  Result := True;
end;

procedure TMemScan.Free();
begin
  if Self.Proc <> 0 then
     CloseHandle(Self.Proc);
  Self.Proc     := 0;
  Self.SysMemLo := 0;
  Self.SysMemHi := 0;
end;


function TMemScan.GetMemRange(low,high:PtrUInt; dataSize:Int32; Alignment:Int8): TPtrInfoArray;
var
  lo,hi,k:Int32;
  overhead,count,buf_size:Int32;
  memInfo: MEMORY_BASIC_INFORMATION;
  gotBytes, procMinAddr, procMaxAddr:PtrUInt;
  buffer:PChar;
begin
  alignment := max(alignment, 1);
  procMinAddr := Max(low,  Self.SysMemLo);
  procMaxAddr := Min(high, Self.SysMemHi);

  buf_size := 5 * 1024 * 1024;
  buffer   := GetMem(buf_size);

  SetLength(Result, 1024);
  overhead := 1024;
  count := 0;
  while procMinAddr < procMaxAddr do
  begin
    VirtualQueryEx(Self.Proc, pointer(procMinAddr), {out} memInfo, SizeOf(memInfo));

    if (MemInfo.State = MEM_COMMIT) and (not (MemInfo.Protect = PAGE_GUARD) or
       (MemInfo.Protect = PAGE_NOACCESS)) and (MemInfo.Protect = PAGE_READWRITE) then
    begin
      if memInfo.RegionSize > buf_size then
      begin
        buffer := ReAllocMem(buffer, memInfo.RegionSize);
        buf_size := memInfo.RegionSize;
      end;

      if ReadProcessMemory(Self.Proc, memInfo.BaseAddress, buffer, memInfo.RegionSize, {out} gotBytes) then
      begin
        //append the buffer to the result
        lo := 0;
        if PtrUInt(memInfo.BaseAddress) < procMinAddr then
          lo += procMinAddr - PtrUInt(memInfo.BaseAddress);
        if alignment <> 1 then
          lo += alignment - ((PtrUInt(memInfo.BaseAddress)+lo) mod alignment);
        hi := memInfo.RegionSize - dataSize;

        while lo <= hi do
        begin
          //overallocate result
          if (count >= overhead) then
          begin
            overhead += overhead;
            SetLength(Result, overhead);
          end;

          //set result
          Result[count].addr := PtrUInt(memInfo.BaseAddress) + lo;
          SetLength(Result[count].raw, dataSize);
          Move(buffer[lo], Result[count].raw[0], dataSize);
          inc(count);
          lo += alignment;
          if Result[count-1].addr >= procMaxAddr then
            Break;
        end;
      end;
    end;
    // move to the next mem-chunk
    procMinAddr += memInfo.RegionSize;
  end;

  FreeMem(buffer);
  SetLength(Result, count);
end;


function TMemScan.CopyMem(addr:Pointer; bytesToRead:Int32): TByteArray;
var
  gotBytes:PtrUInt;
begin
  SetLength(Result, bytesToRead);
  ReadProcessMemory(Self.Proc, addr, @Result[0], bytesToRead, {out} gotBytes);
end;


(*
  Scans the procceess defined by `pid`, it will then return all addresses which
  matches the given target-value `targetData`. targetData can be any size `targetSize`,
  and will be compared using `CompareMem(...)`

  Alignment is the memory alignment, for example `4` bytes, can be used to skip some unwated matches.
*)
function TMemScan.Search(targetData:Pointer; targetSize:Int32; Alignment:Int8): TPtrIntArray;
var
  lo,hi:Int32;
  overhead,count,buf_size:Int32;
  memInfo: MEMORY_BASIC_INFORMATION;
  gotBytes, procMinAddr, procMaxAddr:PtrUInt;
  buffer:PChar;
begin
  alignment := max(alignment, 1);
  procMinAddr := Self.SysMemLo;
  procMaxAddr := Self.SysMemHi;

  buf_size := 5 * 1024 * 1024;
  buffer   := GetMem(buf_size);

  SetLength(Result, 1024);
  overhead := 1024;
  count := 0;

  while procMinAddr < procMaxAddr do
  begin
    VirtualQueryEx(Self.Proc, pointer(procMinAddr), {out} memInfo, SizeOf(memInfo));

    if (MemInfo.State = MEM_COMMIT) and (not (MemInfo.Protect = PAGE_GUARD) or
       (MemInfo.Protect = PAGE_NOACCESS)) and (MemInfo.Protect = PAGE_READWRITE) then
    begin
      if memInfo.RegionSize > buf_size then
      begin
        buffer := ReAllocMem(buffer, memInfo.RegionSize);
        buf_size := memInfo.RegionSize;
      end;

      if ReadProcessMemory(Self.Proc, memInfo.BaseAddress, buffer, memInfo.RegionSize, {out} gotBytes) then
      begin
        // scan the buffer for given value
        lo := 0;
        hi := memInfo.RegionSize - targetSize;
        if alignment <> 1 then
          lo += alignment - (PtrUInt(memInfo.BaseAddress) mod alignment);

        while lo <= hi do
        begin
          if CompareMem(targetData, @buffer[lo], targetSize) then
          begin
            if (count = overhead) then //overallocate result
            begin
              overhead += overhead;
              SetLength(Result, overhead);
            end;
            Result[count] := PtrUInt(memInfo.BaseAddress) + lo;
            inc(count);
          end;
          lo += alignment;
        end;
      end;
    end;
    // move to the next mem-chunk
    procMinAddr += memInfo.RegionSize;
  end;

  FreeMem(buffer);
  SetLength(Result, count);
end;



function CompareLongboolMask(mem,mask:Pointer; len:Int32): Boolean; inline;
var i:Int32 = 0;
begin
  while i < len do
  begin
    if (PUInt32(mem)^ <> 0) <> (PUInt32(mask)^ <> 0) then
      Exit(False);
    inc(mem, SizeOf(LongBool));
    inc(mask, SizeOf(LongBool));
    Inc(i,SizeOf(LongBool));
  end;
  Result := True;
end;

(*
  Scans the procceess defined by `pid`, it will then return all addresses which
  matches the given target-mask `maskData`. maskData can be any size `maskSize`.
  - targetData is a simple boolean-mask.

  Alignment is the memory alignment, for example `4` bytes, can be used to achieve
  better speed, and skip some unwated matches.

  Be warned the result can quickly get far to big with small masks!
*)
function TMemScan.SearchBoolMask(maskData:Pointer; maskSize:Int32; Alignment:Int8): TPtrIntArray;
var
  lo,hi:Int32;
  overhead,count,buf_size:Int32;
  memInfo: MEMORY_BASIC_INFORMATION;
  gotBytes, procMinAddr, procMaxAddr:PtrUInt;
  buffer:PChar;
begin
  alignment := max(alignment, 1);

  procMinAddr := Self.SysMemLo;
  procMaxAddr := Self.SysMemHi;

  buf_size := 5 * 1024 * 1024;
  buffer   := GetMem(buf_size);

  SetLength(Result, 1024);
  overhead := 1024;
  count := 0;

  while procMinAddr < procMaxAddr do
  begin
    VirtualQueryEx(Self.Proc, pointer(procMinAddr), {out} memInfo, SizeOf(memInfo));

    if (MemInfo.State = MEM_COMMIT) and (not (MemInfo.Protect = PAGE_GUARD) or
       (MemInfo.Protect = PAGE_NOACCESS)) and (MemInfo.Protect = PAGE_READWRITE) then
    begin
      if memInfo.RegionSize > buf_size then
      begin
        buffer := ReAllocMem(buffer, memInfo.RegionSize);
        buf_size := memInfo.RegionSize;
      end;

      if ReadProcessMemory(Self.Proc, memInfo.BaseAddress, buffer, memInfo.RegionSize, {out} gotBytes) then
      begin
        // scan the buffer for given value
        lo := 0;
        hi := memInfo.RegionSize - maskSize;
        if alignment <> 1 then
          lo += alignment - (PtrUInt(memInfo.BaseAddress) mod alignment);

        while lo <= hi do
        begin
          if CompareLongboolMask(@buffer[lo], maskData, maskSize) then
          begin
            if (count = overhead) then //overallocate result
            begin
              overhead += overhead;
              SetLength(Result, overhead);
            end;
            Result[count] := PtrUInt(memInfo.BaseAddress) + lo;
            inc(count);
          end;
          lo += alignment;
        end;
      end;
    end;
    // move to the next mem-chunk
    procMinAddr += memInfo.RegionSize;
  end;

  FreeMem(buffer);
  SetLength(Result, count);
end;



//----------------------------------------------------------------------------|\
//---| WRAPPERS |-------------------------------------------------------------||
//----------------------------------------------------------------------------|/
function TMemScan_Init(var scan:TMemScan; pid:UInt32): Boolean; cdecl;
begin
  Result := scan.Init(pid);
end;

procedure TMemScan_Free(var scan:TMemScan); cdecl;
begin
  scan.Free();
end;

function TMemScan_GetMemRange(var scan:TMemScan; low, high:PtrUInt; dataSize:Int32; alignment:Int8): TPtrInfoArray; cdecl;
begin
  Result := scan.GetMemRange(low, high, dataSize, alignment);
end;

function TMemScan_CopyMem(var scan:TMemScan; addr:Pointer; bytesToRead:Int32): TByteArray; cdecl;
begin
  Result := scan.CopyMem(addr, bytesToRead);
end;

function TMemScan_Search(var scan:TMemScan; targetData:Pointer; targetSize:Int32; alignment:Int8): TPtrIntArray; cdecl;
begin
  Result := scan.Search(targetData, targetSize, alignment);
end;

function TMemScan_SearchBoolMask(var scan:TMemScan; maskData:Pointer; maskSize:Int32; alignment:Int8): TPtrIntArray; cdecl;
begin
  Result := scan.SearchBoolMask(maskData, maskSize, alignment);
end;


//---| Helpers |--------------------------------------------------------------\\
// ints
function TMemScan_FindInt8(var scan:TMemScan; data:UInt8; alignment:Int8): TPtrIntArray; cdecl;
begin
  Result := scan.Search(@data, SizeOf(UInt8), alignment);
end;

function TMemScan_FindInt16(var scan:TMemScan; data:UInt16; alignment:Int8): TPtrIntArray; cdecl;
begin
  Result := scan.Search(@data, SizeOf(UInt16), alignment);
end;

function TMemScan_FindInt32(var scan:TMemScan; data:UInt32; alignment:Int8): TPtrIntArray; cdecl;
begin
  Result := scan.Search(@data, SizeOf(UInt32), alignment);
end;

function TMemScan_FindInt64(var scan:TMemScan; data:UInt64; alignment:Int8): TPtrIntArray; cdecl;
begin
  Result := scan.Search(@data, SizeOf(UInt64), alignment);
end;

// floats
function TMemScan_FindFloat(var scan:TMemScan; data:Single; alignment:Int8): TPtrIntArray; cdecl;
begin
  Result := scan.Search(@data, SizeOf(Single), alignment);
end;

function TMemScan_FindDouble(var scan:TMemScan; data:Double; alignment:Int8): TPtrIntArray; cdecl;
begin
  Result := scan.Search(@data, SizeOf(Double), alignment);
end;

// str
function TMemScan_FindString(var scan:TMemScan; data:AnsiString; alignment:Int8): TPtrIntArray; cdecl;
begin
  Result := scan.Search(@data[1], Length(data), alignment);
end;

function TMemScan_FindWideString(var scan:TMemScan; data:WideString; alignment:Int8): TPtrIntArray; cdecl;
begin
  Result := scan.Search(@data[1], Length(data)*2, alignment);
end;

// general
function TMemScan_FindByteArray(var scan:TMemScan; data:TByteArray; alignment:Int8): TPtrIntArray; cdecl;
begin
  Result := scan.Search(@data[0], Length(data), alignment);
end;



{=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=]
 Export our functions, name, information etc...
[=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=}
function GetPluginABIVersion: Integer; cdecl; export;
begin
  Result := 2;
end;

procedure SetPluginMemManager(MemMgr : TMemoryManager); cdecl; export;
begin
  if memisset then
    exit;
  GetMemoryManager(OldMemoryManager);
  SetMemoryManager(MemMgr);
  memisset := true;
end;

procedure OnDetach; cdecl; export;
begin
  SetMemoryManager(OldMemoryManager);
end;


//Count of functions that will be exported...
function GetFunctionCount(): Integer; cdecl; export;
begin Result := 15; end;


//Information about our functions...
function GetFunctionInfo(x: Integer; var ProcAddr: Pointer; var ProcDef: PChar): Integer; cdecl; export;
begin
  case x of
    0:begin
        ProcAddr := @TMemScan_Init;
        StrPCopy(ProcDef, 'function TMemScan.Init(pid:UInt32): Boolean;');
      end;
    1:begin
        ProcAddr := @TMemScan_Free;
        StrPCopy(ProcDef, 'procedure TMemScan.Free();');
      end;
    2:begin
        ProcAddr := @TMemScan_Search;
        StrPCopy(ProcDef, 'function TMemScan.Search(targetData:Pointer; targetSize:Int32; alignment:Int8=1): TPtrIntArray;');
      end;
    3:begin
        ProcAddr := @TMemScan_GetMemRange;
        StrPCopy(ProcDef, 'function TMemScan.GetMemRange(low,high:PtrUInt; dataSize:Int32; alignment:Int8=1): TPtrInfoArray;');
      end;
    4:begin
        ProcAddr := @TMemScan_SearchBoolMask;
        StrPCopy(ProcDef, 'function TMemScan.SearchBoolMask(maskData:Pointer; maskSize:Int32; alignment:Int8=1): TPtrIntArray;');
      end;
    5:begin
        ProcAddr := @TMemScan_CopyMem;
        StrPCopy(ProcDef, 'function TMemScan.CopyMem(addr:PtrUInt; bytesToRead:Int32): TByteArray;');
      end;

    //helpers ------------------------>
    6:begin
        ProcAddr := @TMemScan_FindInt8;
        StrPCopy(ProcDef, 'function TMemScan.FindInt8(data:UInt8; alignment:Int8=1): TPtrIntArray;');
      end;
    7:begin
        ProcAddr := @TMemScan_FindInt16;
        StrPCopy(ProcDef, 'function TMemScan.FindInt16(data:UInt16; alignment:Int8=1): TPtrIntArray;');
      end;
    8:begin
        ProcAddr := @TMemScan_FindInt32;
        StrPCopy(ProcDef, 'function TMemScan.FindInt32(data:UInt32; alignment:Int8=1): TPtrIntArray;');
      end;
    9:begin
        ProcAddr := @TMemScan_FindInt64;
        StrPCopy(ProcDef, 'function TMemScan.FindInt64(data:UInt64; alignment:Int8=1): TPtrIntArray;');
      end;
   10:begin
        ProcAddr := @TMemScan_FindFloat;
        StrPCopy(ProcDef, 'function TMemScan.FindFloat(data:Single; alignment:Int8=1): TPtrIntArray;');
      end;
   11:begin
        ProcAddr := @TMemScan_FindDouble;
        StrPCopy(ProcDef, 'function TMemScan.FindDouble(data:Double; alignment:Int8=1): TPtrIntArray;');
      end;
   12:begin
        ProcAddr := @TMemScan_FindString;
        StrPCopy(ProcDef, 'function TMemScan.FindString(data:AnsiString; alignment:Int8=1): TPtrIntArray;');
      end;
   13:begin
        ProcAddr := @TMemScan_FindWideString;
        StrPCopy(ProcDef, 'function TMemScan.FindWideString(data:WideString; alignment:Int8=1): TPtrIntArray;');
      end;
   14:begin
        ProcAddr := @TMemScan_FindByteArray;
        StrPCopy(ProcDef, 'function TMemScan.FindByteArray(data:TByteArray; alignment:Int8=1): TPtrIntArray;');
      end;
  else
    x := -1;
  end;
  Result := x;
end;

function GetTypeCount(): Integer; cdecl; export;
begin Result := 4; end;

function GetTypeInfo(x: Integer; var sType, sTypeDef: PChar): integer; cdecl; export;
begin
  case x of
    0: begin
        StrPCopy(sType, 'TPtrInfo');
        StrPCopy(sTypeDef, 'record addr: PtrUInt; raw: TByteArray; end;');
       end;
    1: begin
        StrPCopy(sType, 'TPtrInfoArray');
        StrPCopy(sTypeDef, 'Array of TPtrInfo;');
       end;
    2: begin
        StrPCopy(sType, 'TPtrIntArray');
        StrPCopy(sTypeDef, 'Array of PtrUInt;');
       end;
    3: begin
         StrPCopy(sType, 'TMemScan');
         StrPCopy(sTypeDef, 'record Proc: PtrUInt; SysMemLo: PtrUInt; SysMemHi: PtrUInt; end;');
       end;
    else
      x := -1;
  end;

  Result := x;
end;

exports GetPluginABIVersion;
exports SetPluginMemManager;
exports GetTypeCount;
exports GetTypeInfo;
exports GetFunctionCount;
exports GetFunctionInfo;
exports OnDetach;

begin
end.
