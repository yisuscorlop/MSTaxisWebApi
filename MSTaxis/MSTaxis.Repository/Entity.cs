using MSTaxis.IRepository.Infrastructure;
using System.ComponentModel.DataAnnotations.Schema;

namespace MSTaxis.Repository
{
    public abstract class Entity : IObjectState
    {
        [NotMapped]
        public ObjectState ObjectState { get; set; }
    }
}
