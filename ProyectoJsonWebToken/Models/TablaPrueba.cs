﻿using System;
using System.Collections.Generic;

namespace ProyectoJsonWebToken.Models;

public partial class TablaPrueba
{
    public DateTime? FechaCreacion { get; set; }

    public DateTime? FechaExpiracion { get; set; }

    public bool? EsActivo { get; set; }
}
