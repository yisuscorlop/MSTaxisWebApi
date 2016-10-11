using System.Threading;
using System.Threading.Tasks;
using MSTaxis.IRepository.Infrastructure;
using MSTaxis.IRepository.Repositories;


namespace MSTaxis.IRepository.UnitOfWork
{
    public interface IUnitOfWorkAsync : IUnitOfWork
    {
        Task<int> SaveChangesAsync();
        Task<int> SaveChangesAsync(CancellationToken cancellationToken);
        IRepositoryAsync<TEntity> RepositoryAsync<TEntity>() where TEntity : class, IObjectState;
    }
}
