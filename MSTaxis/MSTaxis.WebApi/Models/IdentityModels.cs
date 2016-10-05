using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System.ComponentModel.DataAnnotations;
using System.Configuration;
using System;
using System.Data.Entity;

namespace MSTaxis.WebApi.Models
{

    public class ApplicationUserLogin : IdentityUserLogin<string> { }
    public class ApplicationUserClaim : IdentityUserClaim<string> { }
    public class ApplicationUserRole : IdentityUserRole<string> { }

    // You can add profile data for the user by adding more properties to your ApplicationUser class, please visit http://go.microsoft.com/fwlink/?LinkID=317594 to learn more.
    public class ApplicationUser : IdentityUser<string, ApplicationUserLogin,
     ApplicationUserRole, ApplicationUserClaim>
    {

        public ApplicationUser()
        {
            this.Id = Guid.NewGuid().ToString();
        }

        [Required]
        [StringLength(30, ErrorMessage = "Max 2 digits")]
        public string DocumentType { get; set; }

        [Required]
        [StringLength(30, ErrorMessage = " ")]
        //[Index(IsUnique = true)]
        public string DocumentNumber { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "El mensaje")]
        public string Names { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "Poner mensaje")]
        public string Surnames { get; set; }

        public string Address { get; set; }

        public string CellPhone { get; set; }

        public bool IsActive { get; set; }

        public async Task<ClaimsIdentity> GenerateUserIdentityAsync(ApplicationUserManager manager, string authenticationType)
        {
            // Note the authenticationType must match the one defined 
            // in CookieAuthenticationOptions.AuthenticationType
            var userIdentity =
                await manager.CreateIdentityAsync(this, authenticationType);
            // Add custom user claims here
            return userIdentity;
        }
    }
    public class ApplicationRole : IdentityRole<string, ApplicationUserRole>
    {
        public ApplicationRole()
        {
            this.Id = Guid.NewGuid().ToString();
        }

        public ApplicationRole(string name)
            : this()
        {
            this.Name = name;
        }

        public string Description { get; set; }

        // Add any custom Role properties/code here
    }

    public class ApplicationDbContext : IdentityDbContext<ApplicationUser, ApplicationRole,
     string, ApplicationUserLogin, ApplicationUserRole, ApplicationUserClaim>
    {
        public ApplicationDbContext()
           : base(GetDefaultConnection())
        {
        }

        private static string GetDefaultConnection()
        {
            string connection = ConfigurationManager.ConnectionStrings["dbIdentityEntities"].ConnectionString;
            return connection;
        }

        public static ApplicationDbContext Create()
        {
            return new ApplicationDbContext();
        }
    }

    public class ApplicationUserStore : UserStore<ApplicationUser, ApplicationRole, string,
        ApplicationUserLogin, ApplicationUserRole,
        ApplicationUserClaim>, IUserStore<ApplicationUser, string>,
    IDisposable
    {
        public ApplicationUserStore()
            : this(new IdentityDbContext())
        {
            base.DisposeContext = true;
        }

        public ApplicationUserStore(DbContext context)
            : base(context)
        {
        }
    }

    public class ApplicationRoleStore : RoleStore<ApplicationRole, string, ApplicationUserRole>,
        IQueryableRoleStore<ApplicationRole, string>, IRoleStore<ApplicationRole, string>, IDisposable
    {
        public ApplicationRoleStore()
            : base(new IdentityDbContext())
        {
            base.DisposeContext = true;
        }

        public ApplicationRoleStore(DbContext context)
            : base(context)
        {
        }
    }
}