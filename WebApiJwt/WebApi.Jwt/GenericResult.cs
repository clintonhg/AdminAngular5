﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApi.Jwt
{
    public class GenericResult
    {
        public string[] Errors { get; set; }
        public bool Success { get; set; }
    }

    public class GenericResult<TResult> : GenericResult
    {
        public TResult Result { get; set; }
    }
}