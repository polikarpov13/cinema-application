package cinema.dao.impl;

import cinema.dao.AbstractDao;
import cinema.dao.RoleDao;
import cinema.exception.DataProcessingException;
import cinema.model.Role;
import java.util.Optional;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;

public class RoleDaoImpl extends AbstractDao<Role> implements RoleDao {

    @Autowired
    protected RoleDaoImpl(SessionFactory sessionFactory) {
        super(sessionFactory, Role.class);
    }

    @Override
    public Optional<Role> getByName(String roleName) {
        try (Session session = factory.openSession()) {
            return session.createQuery("SELECT r FROM Role r "
                            + "WHERE r.roleName = :roleName", Role.class)
                    .setParameter("roleName", Role.RoleName.valueOf(roleName))
                    .uniqueResultOptional();
        } catch (Exception e) {
            throw new DataProcessingException("Couldn't get role by role name: "
                    + roleName, e);
        }
    }
}
