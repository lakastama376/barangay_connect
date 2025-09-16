using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace BarangayApp.Areas.Identity.Data;

// Add profile data for application users by adding properties to the ApplicationUser class
public class ApplicationUser : IdentityUser
{
    public string FirstName { get; set; } = "";
    public string LastName { get; set; } = "";
    public string? MiddleName { get; set; }
    public string Address { get; set; } = "";
    public string Gender { get; set; } = "";
    public int Age { get; set; }
    public DateTime CreatedAt { get; set; }
    public string? BarangayCertificatePath { get; set; }
}

