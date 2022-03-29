library IChecksum;

uses
  System.SysUtils,
  System.StrUtils,
  System.Classes,
  HlpHashLibTypes,
  {CRC32}
  HlpCRC32Fast,
  {MD5}
  HlpMD5,
  {SHA1}
  HlpSHA1,
  {XXH32}
  HlpXXHash32;

{$R *.res}

type
  TCheckHashes = procedure(Filename: String;
    FileProgress, TotalFiles, FilesProcessed, StatusCode: Integer;
    StopHash: Word) of Object;

type
  THashType = (CRC32, MD5, SHA1, XXHash32);

function FileSize(Filename: String): Int64;
var
  sr: TSearchRec;
begin
  if FindFirst(Filename, faAnyFile, sr) = 0 then
    result := Int64(sr.FindData.nFileSizeHigh) shl Int64(32) +
      Int64(sr.FindData.nFileSizeLow)
  else
    result := -1;
  FindClose(sr);
end;

procedure SeparateHexFromLine(Filename: String; HashLength: Integer;
  var HashHexList, HashFileLoc: TStringlist);
var
  TempStrLst: TStringlist;
  intIndex, I: Integer;
  Source, Target: string;
begin
  TempStrLst := TStringlist.Create;
  TempStrLst.LoadFromFile(Filename);
  Try
    // Remove lines which commented
    intIndex := 0;
    while intIndex < TempStrLst.Count do
    begin
      if (AnsiContainsStr(TempStrLst.Strings[intIndex], ';')) then
        TempStrLst.Delete(intIndex)
      else
        Inc(intIndex);
    end;

    // GetHashHex
    for I := 0 to (TempStrLst.Count - 1) do
    begin
      Source := TempStrLst.Strings[I];
      Target := Copy(Source, 0, HashLength); // HashLenght for crc32 = 8
      HashHexList.Add(Target);
    end;

    // GetHashFileLoc
    for I := 0 to (TempStrLst.Count - 1) do
    begin
      Source := TempStrLst.Strings[I];
      Target := Copy(Source, HashLength + 3, Length(Source));
      HashFileLoc.Add(Target);
    end;
  Finally
    TempStrLst.Free;
  End;
end;

function CheckHashAlgo(Filename: String; HashLength: Integer): Boolean;
var
  TempStrLst2: TStringlist;
  intIndex, I: Integer;
  CheckChar: Char;
begin
  TempStrLst2 := TStringlist.Create;
  TempStrLst2.LoadFromFile(Filename);
  try
    intIndex := 0;
    while intIndex < TempStrLst2.Count do
    begin
      if (AnsiContainsStr(TempStrLst2.Strings[intIndex], ';')) then
        TempStrLst2.Delete(intIndex)
      else
        Inc(intIndex);
    end;
    for I := 0 to (TempStrLst2.Count - 1) do
    begin
      CheckChar := TempStrLst2.Strings[I].Chars[HashLength];
      if CheckChar = '*' then
      begin
        result := true;
        break;
      end
      else
      begin
        result := false;
        break;
      end;
    end;
  finally
    TempStrLst2.Free;
  end;
end;

const
  BUFFERSIZE = Int32(64 * 1024);

procedure CalculateHashes(WorkDir: String; FFilename: String;
  FHashType: THashType; ChecksumProgress: TCheckHashes;
  var StopHash: Word); stdcall;
var
  BytesRead, StatusCode, I, HashLen: Integer;
  FromFile: file;
  { CRC32 }
  ICHKSUM1: TCRC32_PKZIP;
  { MD5 }
  ICHKSUM2: TMD5;
  { SHA1 }
  ICHKSUM3: TSHA1;
  { XXH32 }
  ICHKSUM4: TXXHASH32;
  LData: THashLibByteArray;
  TotalKB, pMB, nMB, cPB: Int64;
  FileProcessed, TotalFiles: Integer;
  HashFileList, HashHexList: TStringlist;
  HashFile, HashResult: String;
begin
  if FileExists(FFilename) and DirectoryExists(WorkDir) then
  begin
    HashFileList := TStringlist.Create;
    HashHexList := TStringlist.Create;
    case FHashType of
      CRC32:
        begin
          HashLen := 8;
          ICHKSUM1 := TCRC32_PKZIP.Create;
          ICHKSUM1.Initialize;
        end;
      MD5:
        begin
          HashLen := 32;
          ICHKSUM2 := TMD5.Create;
          ICHKSUM2.Initialize;
        end;
      SHA1:
        begin
          HashLen := 40;
          ICHKSUM3 := TSHA1.Create;
          ICHKSUM3.Initialize;
        end;
      XXHash32:
        begin
          HashLen := 8;
          ICHKSUM4 := TXXHASH32.Create;
          ICHKSUM4.Initialize;
        end;
    end;
    if CheckHashAlgo(PChar(FFilename), HashLen + 1) = true then
    begin
      SeparateHexFromLine(PChar(FFilename), HashLen, HashHexList, HashFileList);
      FileProcessed := 0;
      TotalFiles := HashFileList.Count;
      try
        for I := 0 to HashFileList.Count - 1 do
        begin
          HashFile := IncludeTrailingPathDelimiter(WorkDir) +
            PChar(HashFileList.Strings[I]);
          if StopHash = 1 then
          begin
            ChecksumProgress('', 1000, TotalFiles, TotalFiles, -3, 0);
            break;
          end;
          if not FileExists(HashFile) then
          begin
            FileProcessed := FileProcessed + 1;
            ChecksumProgress(ExtractFileName(HashFile), 0, TotalFiles,
              FileProcessed, -2, 0);
          end
          else
          begin
            try
              ASSIGN(FromFile, HashFile);
              nMB := FileSize(HashFile);
{$I-}
              Reset(FromFile, 1);
{$I+}
              StopHash := IOResult;
              if StopHash = 0 then
              begin
                TotalKB := 0;
                StatusCode := 1;
                System.SetLength(LData, BUFFERSIZE);
                repeat
                  if (StopHash = 1) then
                    ChecksumProgress('', TotalFiles, TotalFiles, 0, -3, 0);
{$I-}
                  BlockRead(FromFile, LData[0], BUFFERSIZE, BytesRead);
{$I+}
                  StopHash := IOResult;
                  if (StopHash = 0) AND (BytesRead > 0) then
                  begin
                    case FHashType of
                      CRC32:
                        begin
                          ICHKSUM1.TransformBytes(LData, 0, BytesRead);
                        end;
                      MD5:
                        begin
                          ICHKSUM2.TransformBytes(LData, 0, BytesRead);
                        end;
                      SHA1:
                        begin
                          ICHKSUM3.TransformBytes(LData, 0, BytesRead);
                        end;
                      XXHash32:
                        begin
                          ICHKSUM4.TransformBytes(LData, 0, BytesRead);
                        end;
                    end;
                    pMB := TotalKB;
                    cPB := Round(1000 * (pMB / nMB));
                    ChecksumProgress(ExtractFileName(HashFile), cPB, TotalFiles,
                      FileProcessed, StatusCode, 0);
                    TotalKB := TotalKB + BytesRead;
                  end
                  until (BytesRead = 0) OR (StopHash > 0);
                  CLOSE(FromFile)
                end;
              finally
                if not(StopHash = 1) then
                begin
                  FileProcessed := FileProcessed + 1;
                  case FHashType of
                    CRC32:
                      begin
                        HashResult := ICHKSUM1.TransformFinal.ToString();
                      end;
                    MD5:
                      begin
                        HashResult := ICHKSUM2.TransformFinal.ToString();
                      end;
                    SHA1:
                      begin
                        HashResult := ICHKSUM3.TransformFinal.ToString();
                      end;
                    XXHash32:
                      begin
                        HashResult := ICHKSUM4.TransformFinal.ToString();
                      end;
                  end;
                  if (HashHexList.Strings[I] = HashResult) then
                    ChecksumProgress(ExtractFileName(HashFile), cPB, TotalFiles,
                      FileProcessed, 0, 0)
                  else
                    ChecksumProgress(ExtractFileName(HashFile), cPB, TotalFiles,
                      FileProcessed, -1, 0);
                end
                else
                  ChecksumProgress(HashFile, 1000, TotalFiles,
                    TotalFiles, -3, 0);
              end;
            end;
          end;
        finally
          if not(StopHash = 1) then
            ChecksumProgress('', 1000, TotalFiles, TotalFiles, 1, 0);
          HashHexList.Free;
          HashFileList.Free;
        end;
      end
    else
    begin
      StopHash := 1;
      ChecksumProgress('', 1000, 1, 1, -4, 0);
    end;
  end
  else
  begin
    StopHash := 1;
    ChecksumProgress('', 1000, 1, 1, -5, 0);
  end;
end;

exports
  CalculateHashes;

end.
