REM Copyright (c) Microsoft Corporation
REM SPDX-License-Identifier: MIT

@echo off

SET VS_DEV_CMD_COMMUNITY="%ProgramFiles%\\Microsoft Visual Studio\\2022\\Community\\Common7\\Tools\\VsDevCmd.bat"
SET VS_DEV_CMD_PROFESSIONAL="%ProgramFiles%\\Microsoft Visual Studio\\2022\\Professional\\Common7\\Tools\\VsDevCmd.bat"
SET VS_DEV_CMD_ENTERPRISE="%ProgramFiles%\\Microsoft Visual Studio\\2022\\Enterprise\\Common7\\Tools\\VsDevCmd.bat"

IF EXIST %VS_DEV_CMD_ENTERPRISE% (
    SET VS_DEV_CMD=%VS_DEV_CMD_ENTERPRISE%
) ELSE (
    IF EXIST %VS_DEV_CMD_PROFESSIONAL% (
        SET VS_DEV_CMD=%VS_DEV_CMD_PROFESSIONAL%
    ) ELSE (
        IF EXIST %VS_DEV_CMD_COMMUNITY% (
            SET VS_DEV_CMD=%VS_DEV_CMD_COMMUNITY%
        ) ELSE (
            ECHO "No VS 2022 found!"
            EXIT /b 1
        )
    )
)

%VS_DEV_CMD%
